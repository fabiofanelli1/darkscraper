DarkScraper — Dark Web Monitor
The second tool in this project monitors dark web forums (BreachForums, DarkForums, LeakBase, XSS.is, etc.) for posts about potential corporate data breaches. It connects through Tor, searches for your target companies, and alerts you when new threads mention database leaks, credential dumps, or data breaches involving organizations you're monitoring.
What It Does

Scans dark web forums via Tor — Connects through the Tor SOCKS proxy to reach .onion sites, searches forum listings and runs keyword queries with pagination support (up to 5 pages per query, configurable)
Watches for specific companies — You configure a list of target organizations; the tool alerts you when their name appears alongside breach-related keywords (database, leak, dump, credentials, etc.)
Classifies alert severity — Each finding is rated as critical, high, medium, or low based on content analysis (e.g., mentions of SSN, credit cards, or government entities are flagged as critical)
Rotates Tor circuits — Requests a new Tor exit node between monitoring cycles for better anonymity
Encrypts forum credentials — Login credentials for authenticated forums are stored encrypted with AES-256, just like VulnWatch cookies
Collects metadata only — The tool reads post titles, authors, dates, and view counts. It does NOT download, purchase, or interact with any leaked data

Requirements
bashpip install requests[socks] beautifulsoup4 rich cryptography stem

# Install and start Tor
sudo dnf install tor           # Fedora
sudo systemctl start tor
Setup
1. Configure forum URLs — Edit FORUM_DEFINITIONS in dark_scraper.py and add current .onion URLs. Dark web forum addresses change frequently — check sites like dark.fail for current mirrors.
2. Add your target companies:
pythonWATCH_TARGETS = [
    "Acme Corp",
    "Globex Corporation",
    "Example Bank",
]
3. (Optional) Save forum credentials:
bashpython dark_scraper.py --setup-creds
4. Run:
bash# Monitor specific companies
python dark_scraper.py --targets "Acme Corp" "Example Bank"

# Single scan (no loop)
python dark_scraper.py --once

# Custom interval (15 minutes)
python dark_scraper.py --interval 900

# Scrape up to 3 pages per query (less traffic)
python dark_scraper.py --max-pages 3
Example Output
🔍 DarkScraper — Dark Web Breach Monitor
ℹ️  Monitoring 2 targets:
ℹ️    • Acme Corp
ℹ️    • Example Bank
✅ Connected to Tor (exit IP: 185.xxx.xxx.xxx)
✅ Monitor started. Press Ctrl+C to stop.

🔄 CYCLE #1 — 2026-02-17 14:00:01
───── BreachForums ─────

🚨 ═══ ALERT #1 [CRITICAL] ═══
📋 Forum: BreachForums
👤 Author: @threat_actor_123
📅 Date: 2026-02-17
📌 Title: [SELLING] Acme Corp Full Database — 2.3M records with SSN
💬 Replies: 45
👁  Views: 12,891
🔑 Keywords: database, SSN
⚠️  Severity: CRITICAL
CLI Options
FlagDefaultDescription--targetsfrom configCompany names to monitor--interval600Seconds between cycles (default: 10 min)--max-pages5Max pages to scrape per query/listing (1-20)--once—Single scan, no loop--setup-creds—Interactive encrypted credential setup--credsforum_creds.encPath to encrypted credentials file
Important Notes

Forum URLs change frequently — .onion addresses for BreachForums and similar sites get taken down and reappear at new addresses regularly. You'll need to update FORUM_DEFINITIONS when this happens
CSS selectors may break — Forum software updates can change the HTML structure. If parsing stops working, inspect the forum's HTML and update the selectors dict
Authentication is often required — Most forums require an account to search. Use --setup-creds to store login credentials securely
Tor must be running — The script will not work without an active Tor service on port 9050


Recommended .gitignore
cookies.txt
cookies.enc
forum_creds.enc
__pycache__/
*.pyc

Disclaimer
These tools are intended for authorized security research and defensive threat intelligence purposes only. Scraping X.com may violate their Terms of Service. Accessing dark web forums may have legal implications depending on your jurisdiction — ensure you have proper authorization and comply with all applicable laws. The tools collect publicly visible metadata only and do NOT download, purchase, or interact with any stolen data. The authors are not responsible for any misuse or consequences resulting from the use of these tools.

License
MIT License — see LICENSE for details.
