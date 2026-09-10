# MHZALY Autonomous SOC — Setup

## Kya hai ye
`scheduler.py` background mein 24/7 chalta hai (Streamlit se alag), targets ko
har X minute mein scan karta hai, aur sirf **naye** findings Discord pe
bhejta hai. Streamlit app tumhara existing dashboard hi rehta hai — bas
`dashboard_tab.py` ka code paste karke ek naya tab add kar dena.

## Files
- `db.py` — SQLite persistence (targets, scan runs, findings, alert log)
- `connectors.py` — sab APIs/recon logic (NVD, VirusTotal, AbuseIPDB, crt.sh,
  ZoomEye, urlscan.io, ports/SSL/DNS/fuzzing)
- `notifier.py` — Discord webhook sender
- `scheduler.py` — asli 24/7 engine + CLI
- `dashboard_tab.py` — Streamlit tab jo scheduler ka data dikhata hai (read-only)

## Setup steps

1. **Discord webhook banao:** Discord server → Settings → Integrations →
   Webhooks → New Webhook → Copy Webhook URL.

2. **API keys nikalo (sab free tier):**
   - NVD: https://nvd.nist.gov/developers/request-an-api-key (optional, bina key ke bhi chal jata hai, thoda slow)
   - VirusTotal: https://www.virustotal.com/gui/join-us (free account → API key in profile)
   - AbuseIPDB: https://www.abuseipdb.com/register (free tier, 1000 checks/day)
   - ZoomEye: https://www.zoomeye.org/ (free account, limited monthly quota)
   - urlscan.io: https://urlscan.io/user/signup (optional — public search works without key too)

3. **`config.json` banega apne aap** jab pehli baar `scheduler.py` chalao —
   usme keys aur webhook URL bhar dena:
   ```json
   {
     "discord_webhook_url": "https://discord.com/api/webhooks/...",
     "nvd_api_key": "",
     "virustotal_api_key": "",
     "abuseipdb_api_key": "",
     "zoomeye_api_key": "",
     "urlscan_api_key": "",
     "poll_interval_seconds": 60
   }
   ```

4. **Targets add karo:**
   ```bash
   python3 scheduler.py add example.com 60      # har 60 min mein scan
   python3 scheduler.py list
   ```

5. **Scheduler chalao (ye 24/7 chalna chahiye):**
   ```bash
   nohup python3 scheduler.py run &
   ```
   Ya behtar: systemd service bana lo taake reboot ke baad bhi khud chal jaye.
   Agar Streamlit Cloud pe host kar rahe ho, scheduler ko alag se ek chhoti
   VPS (free tier: Oracle Cloud, Fly.io) pe chalana padega — Streamlit Cloud
   khud background process allow nahi karta.

6. **Streamlit dashboard mein tab add karo:** `dashboard_tab.py` ka function
   `render_autonomous_tab()` apne `app.py` ke sidebar radio menu mein
   "Autonomous SOC" option ke against call kar do.

## Kaam kaise karta hai
- Har scan cycle recon + APIs chalata hai, har result ek "fingerprint" (hash)
  banta hai.
- Agar fingerprint pehle se DB mein hai → sirf `last_seen` update, koi alert nahi.
- Agar naya hai → DB mein save + Discord pe alert.
- Isi se "har baar poora dump" ki jagah "sirf naya kya hai" milta hai — real
  SOC analyst jaisa behavior.

## Testing (bina 24/7 chalaye)
```bash
python3 scheduler.py scan-once example.com
```
Ek hi scan cycle turant chala kar dekh sakte ho ke sab thik kaam kar raha hai.
