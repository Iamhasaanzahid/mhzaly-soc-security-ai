#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scheduler.py — The "khud ba khud" (autonomous) engine.

Run this as a long-lived background process (systemd service, screen/tmux
session, or `nohup python3 scheduler.py &`). It is the ONLY thing that runs
24/7 — Streamlit stays a normal request-driven dashboard that just reads
whatever this script has written to the shared SQLite DB.

Usage:
    python3 scheduler.py run                    # start the infinite monitoring loop
    python3 scheduler.py add example.com        # add a target
    python3 scheduler.py add example.com 30     # add with a 30-min scan interval
    python3 scheduler.py list                   # list active targets
    python3 scheduler.py remove <id>            # deactivate a target
    python3 scheduler.py scan-once example.com  # run one scan cycle immediately (testing)
    python3 scheduler.py run-all-once           # run scan for all active targets in DB

v2 changes:
    - Fixed a crash bug in `list`: was reading t['last_scenned_at'] (typo),
      the actual DB column is `last_scanned_at`.
    - run_scan_cycle() now checks the target against connectors.assert_public_host()
      once up front — if it resolves to an internal/reserved/metadata address,
      the whole cycle is skipped and a warning is sent to Discord instead of
      silently port-scanning or fetching your own internal network.
    - nvd_search() calls now default to strict (CPE-confirmed) CVE matching,
      since this path alerts unattended with no human review.
"""

import sys
import os
import time
import json
import logging
from datetime import datetime

try:
    from . import db
    from . import connectors as c
    from . import notifier
    from . import advanced_features as af
    from . import confidence
    from . import hunter
except ImportError:
    try:
        from core import db
        from core import connectors as c
        from core import notifier
        from core import advanced_features as af
        from core import confidence
        from core import hunter
    except ImportError:
        import db
        import connectors as c
        import notifier
        import advanced_features as af
        import confidence
        import hunter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mhzaly-scheduler")

CONFIG_PATH = "config.json"
DEFAULT_CONFIG = {
    "discord_webhook_url": "",
    "nvd_api_key": "",
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "zoomeye_api_key": "",
    "urlscan_api_key": "",
    "poll_interval_seconds": 60,
    "strict_cve_matching": True,
    "report_min_confidence": 70,
    "report_min_severity": "MEDIUM",
    "web_surface_max_pages": 15,
}

# Maps config.json keys to the environment variable that overrides them.
# This is what makes GitHub Actions (or any CI/systemd setup that injects
# secrets as env vars rather than a committed config.json) actually work —
# without this, load_config() only ever reads the file and silently runs
# with every API key blank, since nobody wants real secrets committed to git.
ENV_OVERRIDES = {
    "discord_webhook_url": "DISCORD_WEBHOOK_URL",
    "slack_webhook_url": "SLACK_WEBHOOK_URL",
    "teams_webhook_url": "TEAMS_WEBHOOK_URL",
    "nvd_api_key": "NVD_API_KEY",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "zoomeye_api_key": "ZOOMEYE_API_KEY",
    "urlscan_api_key": "URLSCAN_API_KEY",
}


def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        merged = {**DEFAULT_CONFIG, **cfg}
    except FileNotFoundError:
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        logger.warning(f"Created blank {CONFIG_PATH} — fill in your API keys and webhook URL, "
                        f"or set the matching environment variables instead.")
        merged = dict(DEFAULT_CONFIG)

    # Environment variables win over config.json when both are present, so a
    # CI runner with no (or a blank) config.json still picks up secrets.
    for cfg_key, env_key in ENV_OVERRIDES.items():
        env_val = os.environ.get(env_key)
        if env_val:
            merged[cfg_key] = env_val

    missing = [env_key for cfg_key, env_key in ENV_OVERRIDES.items()
               if not merged.get(cfg_key) and cfg_key != "urlscan_api_key"]
    if missing:
        logger.warning(f"Running with no value set for: {', '.join(missing)} "
                        f"(checked config.json and environment) — those checks will be skipped.")

    return merged


def safe_notify_alert(cfg: dict, target: str, category: str, severity: str,
                       summary: str, details: dict) -> None:
    """Best-effort Discord alert.

    A broken/missing webhook must never abort a scan cycle: findings are
    already persisted in SQLite by the time we get here, and an exception
    escaping this call used to kill the whole run (and with it the DB commit
    step in GitHub Actions).
    """
    try:
        notifier.send_discord_alert(cfg.get("discord_webhook_url", ""), target,
                                    category, severity, summary, details)
    except Exception as e:
        logger.warning(f"Discord alert failed for {target}: {e}")


def safe_notify_text(cfg: dict, message: str) -> None:
    """Best-effort Discord text message (scan summaries / errors)."""
    try:
        notifier.send_discord_text(cfg.get("discord_webhook_url", ""), message)
    except Exception as e:
        logger.warning(f"Discord notification failed: {e}")


def alert_finding(cfg: dict, target: str, category: str, severity: str,
                  summary: str, details: dict) -> None:
    """Fan an alert out to every configured SIEM channel (Discord + Slack +
    MS Teams). Best-effort: each channel is independent, failures never raise.

    Note (2026-10): this function used to call itself unconditionally as its
    first statement, which meant every new finding raised RecursionError and
    aborted the rest of the scan cycle. It now delegates to safe_notify_alert.
    """
    safe_notify_alert(cfg, target, category, severity, summary, details)
    channels = {
        "discord": cfg.get("discord_webhook_url", ""),
        "slack": cfg.get("slack_webhook_url", ""),
        "teams": cfg.get("teams_webhook_url", ""),
    }
    external = {k: v for k, v in channels.items() if k != "discord" and v}
    if not external:
        return
    try:
        af.send_multi_siem_alert(
            {**channels, **external},
            f"[{severity}] {category} — {target}",
            summary,
            severity,
        )
    except Exception as e:
        logger.warning(f"SIEM fan-out failed: {e}")


def _fanout_error(cfg: dict, message: str) -> None:
    """Best-effort error text fan-out (Slack / MS Teams) — never raises."""
    channels = {
        "discord": cfg.get("discord_webhook_url", ""),
        "slack": cfg.get("slack_webhook_url", ""),
        "teams": cfg.get("teams_webhook_url", ""),
    }
    external = {k: v for k, v in channels.items() if k != "discord" and v}
    if not external:
        return
    try:
        af.send_multi_siem_alert(
            {**channels, **external},
            f"⚠️ SOC alert: {message}",
            message,
            "HIGH",
        )
    except Exception as e:
        logger.warning(f"SIEM fan-out (error) failed: {e}")


def run_scan_cycle(target: str, target_id: int, cfg: dict):
    """One scan of one target, behind a verification gate.

    Every observation is first a *candidate*. Only candidates that clear the
    configured confidence and severity floors are written to the findings table
    and counted as new; only verified, material findings are allowed to page a
    human. The rest are counted and dropped, which is why the report stays
    short enough to be read.
    """
    host = c.clean_host(target)
    run_id = db.start_scan_run(target_id)
    candidates = []
    logger.info(f"Scanning {target} ...")

    # SSRF / scope guard — check once up front so the whole cycle skips cleanly
    # rather than each sub-call silently failing/blocking individually.
    try:
        c.assert_public_host(host)
    except c.ScopeViolation as e:
        db.finish_scan_run(run_id, "BLOCKED", 0, error=str(e))
        logger.warning(f"Scan blocked for {target}: {e}")
        safe_notify_text(
            cfg,
            f"🚫 Scan blocked for `{target}`: resolves to a non-public address. Removing from active scope is recommended."
        )
        return

    try:
        # 1. Deterministic network facts (always run)
        dns_data = c.check_dns(host)  # inventory only, surfaced in logs
        ports = c.scan_ports(host)
        risky = {21, 25, 445, 1433, 3306, 3389, 5432, 9200}
        for p in ports:
            is_risky = p["port"] in risky
            candidates.append({
                "kind": "risky_port" if is_risky else "open_port",
                "category": "Open Port",
                "severity": "MEDIUM" if not is_risky else "MEDIUM",
                "summary": f"Port {p['port']}/{p['service']} reachable from the internet",
                "marker": f"port:{p['port']}",
                "details": p,
                "evidence": {"verified": True},
                "verified": True,
            })

        # 2. Certificate transparency — inventory only. Subdomains are not
        #    vulnerabilities; keeping them out of findings is what stops the
        #    report turning into a list of 400 hostnames nobody reads.
        subdomains = c.crtsh_subdomains(host)

        # 3. Verified web-surface hunt (headers, cookies, TLS, CORS, exposed
        #    files with signature checks, crawl inventory, email auth records)
        web = hunter.scan_web(host, {"max_pages": cfg.get("web_surface_max_pages", 15)})
        candidates.extend(web.get("findings", []))
        inventory = web.get("inventory", {})

        # 4. CVE correlation against the fingerprinted stack. Only CPE-backed
        #    matches are allowed through; keyword hits are leads, not findings.
        for term in [t for t in (inventory.get("technologies") or []) if len(t) >= 3][:2]:
            for cve in c.nvd_search(term, cfg.get("nvd_api_key", ""),
                                    strict=cfg.get("strict_cve_matching", True)):
                is_cpe = cve.get("match_confidence") == "cpe"
                candidates.append({
                    "kind": "cve_cpe" if is_cpe else "cve_keyword",
                    "category": "CVE Correlation",
                    "severity": cve.get("severity", "MEDIUM"),
                    "summary": f"{cve['cve_id']} (CVSS {cve['score']}) matches {term}",
                    "marker": cve["cve_id"],
                    "details": cve,
                    "evidence": {"verified": is_cpe, "match_confidence": cve.get("match_confidence")},
                    "verified": is_cpe,
                })

        # 5. Threat reputation — only actionable when multiple engines agree.
        vt = c.virustotal_check(host, cfg.get("virustotal_api_key", ""))
        if vt.get("malicious", 0) >= 2:
            candidates.append({
                "kind": "vt_malicious",
                "category": "Threat Intelligence",
                "severity": "CRITICAL",
                "summary": f"{vt['malicious']} reputation engines flag the host as malicious",
                "marker": f"vt:{vt['malicious']}",
                "details": vt,
                "evidence": {"verified": True},
                "verified": True,
            })

        # 6. The gate
        kept = confidence.gate(
            candidates,
            min_confidence=cfg.get("report_min_confidence", 70),
            min_severity=cfg.get("report_min_severity", "MEDIUM"),
        )
        new_count = 0
        alerted = 0
        for f in kept:
            fp = db.make_fingerprint(target, f["category"], f["marker"])
            details = dict(f.get("details") or {})
            details["_confidence"] = f["confidence"]
            details["_verified"] = f["verified"]
            is_new = db.upsert_finding(
                target_id, f["category"], fp, f["summary"], details, f["severity"],
                confidence=f["confidence"], verified=f["verified"],
            )
            if is_new:
                new_count += 1
                if confidence.should_alert(f):
                    alerted += 1
                    alert_finding(cfg, target, f["category"], f["severity"],
                                  f["summary"], details)

        db.mark_scanned(target_id)
        db.finish_scan_run(run_id, "SUCCESS", new_count)
        logger.info(
            f"Done: {host} — {len(candidates)} candidate(s), {len(kept)} reported, "
            f"{len(candidates) - len(kept)} suppressed, {new_count} new, {alerted} alerted "
            f"({len(subdomains)} subdomains kept as inventory only)."
        )

    except Exception as e:
        db.finish_scan_run(run_id, "ERROR", 0, error=str(e))
        logger.error(f"Scan failed for {target}: {e}")
        _fanout_error(cfg, f"⚠️ Scan error on `{target}`: {e}")


def run_forever():
    db.init_db()
    cfg = load_config()
    logger.info("MHZALY Autonomous SOC scheduler started. Ctrl+C to stop.")
    last_run = {}  # target_id -> last scan timestamp (epoch)

    while True:
        cfg = load_config()  # re-read so key/webhook edits apply without restart
        targets = db.list_targets(active_only=True)
        now = time.time()
        for t in targets:
            interval_s = t["scan_interval_minutes"] * 60
            if now - last_run.get(t["id"], 0) >= interval_s:
                try:
                    run_scan_cycle(t["target"], t["id"], cfg)
                except Exception as e:
                    # One bad target must not stop the 24/7 monitoring loop.
                    logger.error(f"Unhandled error scanning {t['target']}: {e}")
                last_run[t["id"]] = now
        time.sleep(cfg["poll_interval_seconds"])


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    db.init_db()

    if cmd == "run":
        run_forever()
    elif cmd == "add":
        target = sys.argv[2]
        interval = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        ok = db.add_target(target, interval)
        print(f"Added {target} (every {interval} min)." if ok else f"{target} already exists.")
    elif cmd == "list":
        for t in db.list_targets():
            print(f"[{t['id']}] {t['target']} — every {t['scan_interval_minutes']}min — "
                  f"last scanned: {t['last_scanned_at'] or 'never'}")
    elif cmd == "remove":
        # Soft delete on purpose: keeps findings/scan history (as documented).
        if db.deactivate_target(int(sys.argv[2])):
            print("Deactivated.")
        else:
            print(f"No target with id {sys.argv[2]}.")
    elif cmd == "scan-once":
        target = sys.argv[2]
        db.add_target(target)
        targets = {t["target"]: t["id"] for t in db.list_targets()}
        run_scan_cycle(target, targets[target], load_config())
    elif cmd == "run-all-once":
        targets = db.list_targets(active_only=True)
        if not targets:
            logger.warning("No active targets in the database — nothing to scan.")
            return 0
        cfg = load_config()
        failures = 0
        for t in targets:
            try:
                run_scan_cycle(t["target"], t["id"], cfg)
            except Exception as e:
                failures += 1
                logger.error(f"Unhandled error scanning {t['target']}: {e}")
        if failures:
            # Per-target failures are already recorded in scan_runs and sent to
            # Discord; exiting non-zero here would skip the DB commit step in
            # CI and lose the findings from the targets that DID succeed.
            logger.warning(f"{failures}/{len(targets)} target(s) ended with an unhandled error.")
        return 0
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
