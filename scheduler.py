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
"""

import sys
import time
import json
import logging
from datetime import datetime

import db
import connectors as c
import notifier

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
}


def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        merged = {**DEFAULT_CONFIG, **cfg}
        return merged
    except FileNotFoundError:
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        logger.warning(f"Created blank {CONFIG_PATH} — fill in your API keys and webhook URL.")
        return DEFAULT_CONFIG


def run_scan_cycle(target: str, target_id: int, cfg: dict):
    """One full scan of one target. Every discrete fact goes through
    db.upsert_finding(), which only returns True (→ alert) if it's genuinely new."""
    host = c.clean_host(target)
    new_count = 0
    run_id = db.start_scan_run(target_id)
    logger.info(f"Scanning {target} ...")

    try:
        # 1. DNS + ports + SSL + headers (deterministic, always run)
        dns_data = c.check_dns(host)
        ports = c.scan_ports(host)
        ssl_info = c.check_ssl(host)

        for p in ports:
            fp = db.make_fingerprint(target, "open_port", str(p["port"]))
            is_new = db.upsert_finding(target_id, "open_port", fp,
                                       f"Open port {p['port']} ({p['service']})", p, "MEDIUM")
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "Open Port",
                                           "MEDIUM", f"Port {p['port']}/{p['service']} is open", p)

        # 2. Subdomains via crt.sh
        subs = c.crtsh_subdomains(host)
        for sub in subs:
            fp = db.make_fingerprint(target, "subdomain", sub)
            is_new = db.upsert_finding(target_id, "subdomain", fp,
                                       f"Subdomain discovered: {sub}", {"subdomain": sub}, "INFO")
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "New Subdomain",
                                           "INFO", sub, {"subdomain": sub})

        # 3. Exposed sensitive endpoints
        exposed = c.fuzz_endpoints(f"https://{host}")
        for e in exposed:
            fp = db.make_fingerprint(target, "exposed_endpoint", e["path"])
            is_new = db.upsert_finding(target_id, "exposed_endpoint", fp,
                                       f"Exposed endpoint: {e['path']} ({e['status']})", e, "HIGH")
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "Exposed Endpoint",
                                           "HIGH", e["path"], e)

        # 4. Threat intel (VT + AbuseIPDB) — score changes matter, not just first sight
        vt = c.virustotal_check(host, cfg["virustotal_api_key"])
        if vt.get("malicious", 0) > 0:
            fp = db.make_fingerprint(target, "vt_malicious", str(vt["malicious"]))
            is_new = db.upsert_finding(target_id, "vt_malicious", fp,
                                       f"VirusTotal flags {vt['malicious']} engines as malicious",
                                       vt, "CRITICAL")
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "VirusTotal Flag",
                                           "CRITICAL", f"{vt['malicious']} engines flagged malicious", vt)

        # 5. NVD — correlate against detected tech (kept simple: keyword = host's base name)
        keyword = host.split(".")[0]
        cves = c.nvd_search(keyword, cfg["nvd_api_key"])
        for cve in cves:
            fp = db.make_fingerprint(target, "cve", cve["cve_id"])
            is_new = db.upsert_finding(target_id, "cve", fp,
                                       f"{cve['cve_id']} (CVSS {cve['score']} {cve['severity']})",
                                       cve, cve["severity"])
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "CVE Match",
                                           cve["severity"], cve["cve_id"], cve)

        # 6. ZoomEye — exposed services already indexed
        for zm in c.zoomeye_search(host, cfg["zoomeye_api_key"]):
            fp = db.make_fingerprint(target, "zoomeye_service", f"{zm.get('ip')}:{zm.get('port')}")
            is_new = db.upsert_finding(target_id, "zoomeye_service", fp,
                                       f"ZoomEye: {zm.get('service')} on {zm.get('ip')}:{zm.get('port')}",
                                       zm, "MEDIUM")
            if is_new:
                new_count += 1
                notifier.send_discord_alert(cfg["discord_webhook_url"], target, "ZoomEye Exposure",
                                           "MEDIUM", f"{zm.get('service')} on port {zm.get('port')}", zm)

        db.mark_scanned(target_id)
        db.finish_scan_run(run_id, "SUCCESS", new_count)
        logger.info(f"Done: {target} — {new_count} new finding(s).")

    except Exception as e:
        db.finish_scan_run(run_id, "ERROR", new_count, error=str(e))
        logger.error(f"Scan failed for {target}: {e}")
        notifier.send_discord_text(cfg["discord_webhook_url"], f"⚠️ Scan error on `{target}`: {e}")


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
                run_scan_cycle(t["target"], t["id"], cfg)
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
                  f"last scanned: {t['last_scenned_at'] or 'never'}")
    elif cmd == "remove":
        db.remove_target(int(sys.argv[2]))
        print("Deactivated.")
    elif cmd == "scan-once":
        target = sys.argv[2]
        db.add_target(target)
        targets = {t["target"]: t["id"] for t in db.list_targets()}
        run_scan_cycle(target, targets[target], load_config())
    elif cmd == "run-all-once":
        targets = db.list_targets(active_only=True)
        cfg = load_config()
        for t in targets:
            run_scan_cycle(t["target"], t["id"], cfg)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
