"""
BreachWatch — Dark Web Monitor
=======================================
Monitors dark web forums (BreachForums, LeakBase, etc.) for potential
corporate data breaches. Connects via Tor and searches for keywords
related to data leaks, database dumps, and credential exposures.

This tool is designed for DEFENSIVE threat intelligence only.
It collects post metadata (titles, authors, dates) — it does NOT
download, purchase, or interact with any leaked data.

Requirements:
    pip install requests[socks] beautifulsoup4 rich cryptography stem

    System:
    - Tor service installed and running (sudo dnf install tor && sudo systemctl start tor)

Setup:
    1. Install and start Tor
    2. Configure your target companies in WATCH_TARGETS
    3. Run: python breach_watch.py

Usage:
    python breach_watch.py                              # monitor all targets
    python breach_watch.py --targets "Acme Corp" "Globex"  # specific companies
    python breach_watch.py --interval 900               # every 15 minutes
    python breach_watch.py --once                       # single scan, no loop

Legal Disclaimer:
    This tool is intended for authorized security research and defensive
    threat intelligence. Ensure you comply with all applicable laws in
    your jurisdiction. The authors assume no liability for misuse.
"""

import argparse
import gc
import getpass
import hashlib
import json
import os
import re
import signal
import stat
import sys
import time
import random
from datetime import datetime, timedelta
from urllib.parse import urljoin, quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("❌ requests not installed. Run:")
    print("   pip install requests[socks]")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ beautifulsoup4 not installed. Run:")
    print("   pip install beautifulsoup4")
    sys.exit(1)

try:
    import socks  # PySocks — needed for Tor SOCKS proxy
except ImportError:
    print("❌ PySocks not installed. Run:")
    print("   pip install requests[socks]")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    console = Console()
    USE_RICH = True
except ImportError:
    USE_RICH = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from stem import Signal
    from stem.control import Controller
    HAS_STEM = True
except ImportError:
    HAS_STEM = False


# ─── Configuration ───────────────────────────────────────────────────────────

# Tor SOCKS proxy (default Tor configuration)
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

# Timing
MONITOR_INTERVAL = 600      # seconds between cycles (10 minutes)
REQUEST_TIMEOUT = 30         # seconds per HTTP request
RESULTS_PER_FORUM = 50       # max posts to parse per forum page
MAX_PAGES = 5                # max pages to scrape per query/listing
INTER_REQUEST_PAUSE = (3, 8) # random pause range between requests (seconds)

# User agent rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]


# ─── Forum Definitions ──────────────────────────────────────────────────────
#
# Dark web forums change URLs frequently. These are EXAMPLE structures.
# You MUST update the URLs and CSS selectors to match the current state
# of the forums you want to monitor.
#
# Each forum definition contains:
#   - name: display name
#   - base_url: .onion URL (update as needed)
#   - search_path: URL path for search functionality
#   - selectors: CSS selectors for parsing thread listings
#   - requires_auth: whether login is needed to search
#

FORUM_DEFINITIONS = [
    {
        "name": "BreachForums",
        "base_url": "",  # INSERT .onion URL — changes frequently
        "search_path": "/search.php?action=do_search&keywords={query}&postthread=1&sort=dateline&order=desc",
        "listing_path": "/Forum-Databases",  # main databases/leaks section
        "selectors": {
            "thread_row": "tr.inline_row",
            "thread_title": "span.subject_new a, span.subject_old a",
            "thread_author": "td.forumdisplay_author a",
            "thread_date": "td.forumdisplay_lastpost span",
            "thread_replies": "td:nth-child(4) a",
            "thread_views": "td:nth-child(5)",
            "next_page": "a.pagination_next, a.next",  # MyBB pagination
        },
        "requires_auth": True,
    },
    {
        "name": "DarkForums",
        "base_url": "",  # INSERT .onion URL — changes frequently
        "search_path": "/search.php?action=do_search&keywords={query}&postthread=1&sort=dateline&order=desc",
        "listing_path": "/Forum-Databases",  # databases/leaks section
        "selectors": {
            "thread_row": "tr.inline_row",
            "thread_title": "span.subject_new a, span.subject_old a",
            "thread_author": "td.forumdisplay_author a",
            "thread_date": "td.forumdisplay_lastpost span",
            "thread_replies": "td:nth-child(4) a",
            "thread_views": "td:nth-child(5)",
            "next_page": "a.pagination_next, a.next",  # MyBB pagination
        },
        "requires_auth": True,
    },
    {
        "name": "LeakBase",
        "base_url": "",  # INSERT .onion URL
        "search_path": "/search/?q={query}&o=date",
        "listing_path": "/forums/leaks-and-databases/",
        "selectors": {
            "thread_row": "div.structItem",
            "thread_title": "div.structItem-title a:last-child",
            "thread_author": "a.username",
            "thread_date": "time.u-dt",
            "thread_replies": "dl.pairs--justified dd",
            "thread_views": "dl.pairs--justified:nth-child(2) dd",
            "next_page": "a.pageNav-jump--next",  # XenForo pagination
        },
        "requires_auth": True,
    },
    {
        "name": "XSS.is",
        "base_url": "",  # INSERT .onion URL
        "search_path": "/search/?q={query}&o=date",
        "listing_path": "/forums/databases/",
        "selectors": {
            "thread_row": "div.structItem",
            "thread_title": "div.structItem-title a:last-child",
            "thread_author": "a.username",
            "thread_date": "time.u-dt",
            "thread_replies": "dl.pairs--justified dd",
            "thread_views": "dl.pairs--justified:nth-child(2) dd",
            "next_page": "a.pageNav-jump--next",  # XenForo pagination
        },
        "requires_auth": True,
    },
]

# ─── Watch Targets ───────────────────────────────────────────────────────────
#
# Companies/organizations to monitor for breaches.
# The script searches for each target name combined with breach-related keywords.
#

WATCH_TARGETS = [
    # Add your target companies here
    # "Acme Corp",
    # "Globex Corporation",
    # "Example Bank",
]

# Keywords combined with target names to build search queries
BREACH_KEYWORDS = [
    "database",
    "leak",
    "breach",
    "dump",
    "data",
    "credentials",
    "combo",
    "combolist",
    "accounts",
    "hacked",
    "SQL",
    "SSN",
    "credit card",
]

# Standalone keywords for general breach monitoring (no specific target)
GENERAL_QUERIES = [
]


# ─── Output Utilities ────────────────────────────────────────────────────────

def print_header(text: str):
    if USE_RICH:
        console.print(f"\n[bold cyan]{'═' * 65}[/]")
        console.print(f"[bold white]  {text}[/]")
        console.print(f"[bold cyan]{'═' * 65}[/]\n")
    else:
        print(f"\n{'═' * 65}")
        print(f"  {text}")
        print(f"{'═' * 65}\n")


def print_alert(index: int, alert: dict):
    """Display a single breach alert in the terminal."""
    # Determine severity color based on keyword matches
    severity = alert.get("severity", "medium")
    color_map = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "dim"}
    color = color_map.get(severity, "white")

    if USE_RICH:
        header = Text()
        header.append(f"[{alert['forum']}]", style="bold magenta")
        header.append(f"  @{alert['author']}", style="bold green")
        header.append(f"  •  {alert['date']}", style="dim")

        title = Text(alert["title"])

        stats = Text()
        if alert.get("replies"):
            stats.append(f"💬 {alert['replies']}  ", style="dim")
        if alert.get("views"):
            stats.append(f"👁 {alert['views']}  ", style="dim")
        stats.append(f"⚠️  Severity: ", style="dim")
        stats.append(f"{severity.upper()}", style=f"bold {color}")

        if alert.get("matched_keywords"):
            kw = Text()
            kw.append("🔑 Keywords: ", style="dim")
            kw.append(", ".join(alert["matched_keywords"]), style="italic")
            content = Text.assemble(header, "\n\n", title, "\n\n", stats, "\n", kw)
        else:
            content = Text.assemble(header, "\n\n", title, "\n\n", stats)

        if alert.get("url"):
            link = Text(f"\n🔗 {alert['url']}", style="underline blue")
            content = Text.assemble(content, link)

        console.print(Panel(
            content,
            title=f"[bold {color}]🚨 ALERT #{index}[/]",
            box=box.HEAVY,
            border_style=color,
        ))
    else:
        print(f"\n🚨 === ALERT #{index} [{severity.upper()}] ===")
        print(f"📋 Forum: {alert['forum']}")
        print(f"👤 Author: @{alert['author']}")
        print(f"📅 Date: {alert['date']}")
        print(f"📌 Title: {alert['title']}")
        if alert.get("replies"):
            print(f"💬 Replies: {alert['replies']}")
        if alert.get("views"):
            print(f"👁  Views: {alert['views']}")
        if alert.get("matched_keywords"):
            print(f"🔑 Keywords: {', '.join(alert['matched_keywords'])}")
        if alert.get("url"):
            print(f"🔗 URL: {alert['url']}")
        print()


def print_info(msg: str):
    if USE_RICH:
        console.print(f"[yellow]ℹ️  {msg}[/]")
    else:
        print(f"ℹ️  {msg}")


def print_success(msg: str):
    if USE_RICH:
        console.print(f"[green]✅ {msg}[/]")
    else:
        print(f"✅ {msg}")


def print_error(msg: str):
    if USE_RICH:
        console.print(f"[red]❌ {msg}[/]")
    else:
        print(f"❌ {msg}")


def print_warning(msg: str):
    if USE_RICH:
        console.print(f"[orange1]⚠️  {msg}[/]")
    else:
        print(f"⚠️  {msg}")


# ─── Tor Connection ──────────────────────────────────────────────────────────

def create_tor_session() -> requests.Session:
    """Create a requests session routed through the Tor SOCKS proxy."""
    session = requests.Session()

    # Configure SOCKS5 proxy (Tor)
    proxy_url = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
    session.proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }

    # Retry strategy
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Default headers
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })

    return session


def verify_tor_connection(session: requests.Session) -> bool:
    """Verify that traffic is actually going through Tor."""
    try:
        print_info("Verifying Tor connection...")
        resp = session.get("https://check.torproject.org/api/ip", timeout=REQUEST_TIMEOUT)
        data = resp.json()

        if data.get("IsTor", False):
            print_success(f"Connected to Tor (exit IP: {data.get('IP', 'unknown')})")
            return True
        else:
            print_error("Traffic is NOT going through Tor!")
            return False
    except Exception as e:
        print_error(f"Cannot verify Tor connection: {e}")
        print_info("Make sure Tor is running: sudo systemctl start tor")
        return False


def renew_tor_circuit():
    """Request a new Tor circuit for a fresh exit node."""
    if not HAS_STEM:
        print_warning("stem library not installed — cannot renew Tor circuit.")
        print_info("Install with: pip install stem")
        return False

    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            print_info("🔄 Tor circuit renewed (new exit node).")
            time.sleep(5)  # Wait for new circuit
            return True
    except Exception as e:
        print_warning(f"Cannot renew Tor circuit: {e}")
        print_info("To enable circuit renewal, configure Tor ControlPort:")
        print_info("  Add 'ControlPort 9051' and 'CookieAuthentication 1' to /etc/tor/torrc")
        return False


# ─── Forum Authentication ───────────────────────────────────────────────────

CREDENTIALS_FILE = "forum_creds.enc"
SALT_SIZE = 16


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive an AES-256 key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def save_credentials(creds: dict, enc_path: str):
    """Encrypt and save forum credentials to disk."""
    if not HAS_CRYPTO:
        print_error("cryptography library not installed.")
        sys.exit(1)

    password = getpass.getpass("🔐 Set encryption password: ")
    confirm = getpass.getpass("🔐 Confirm password: ")
    if password != confirm:
        print_error("Passwords don't match.")
        sys.exit(1)

    salt = os.urandom(SALT_SIZE)
    key = _derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(creds).encode())

    with open(enc_path, "wb") as f:
        f.write(salt + encrypted)

    # Set restrictive permissions
    os.chmod(enc_path, stat.S_IRUSR | stat.S_IWUSR)

    del password, confirm, key
    gc.collect()

    print_success(f"Credentials saved to {enc_path}")


def load_credentials(enc_path: str) -> dict:
    """Decrypt and load forum credentials from disk."""
    if not HAS_CRYPTO:
        print_error("cryptography library not installed.")
        sys.exit(1)

    if not os.path.isfile(enc_path):
        return {}

    password = getpass.getpass("🔐 Credentials password: ")

    with open(enc_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    encrypted = data[SALT_SIZE:]

    try:
        key = _derive_key(password, salt)
        fernet = Fernet(key)
        plaintext = fernet.decrypt(encrypted).decode()
        creds = json.loads(plaintext)
    except Exception:
        print_error("Wrong password or corrupted file.")
        del password
        gc.collect()
        sys.exit(1)

    del password, key, plaintext
    gc.collect()

    return creds


def login_to_forum(
    session: requests.Session,
    forum: dict,
    username: str,
    password: str,
) -> bool:
    """
    Attempt to log in to a forum.
    This is a generic handler — you may need to customize it per forum.
    """
    login_url = urljoin(forum["base_url"], "/member.php?action=login")

    try:
        # Get login page (for CSRF tokens)
        resp = session.get(login_url, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract CSRF / hidden fields
        form_data = {}
        hidden_inputs = soup.select('input[type="hidden"]')
        for inp in hidden_inputs:
            name = inp.get("name")
            value = inp.get("value", "")
            if name:
                form_data[name] = value

        form_data["username"] = username
        form_data["password"] = password
        form_data["action"] = "do_login"
        form_data["submit"] = "Login"

        # Submit login
        resp = session.post(login_url, data=form_data, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 200 and "logout" in resp.text.lower():
            print_success(f"Logged in to {forum['name']}.")
            return True
        else:
            print_warning(f"Login to {forum['name']} may have failed.")
            return False

    except Exception as e:
        print_error(f"Login error for {forum['name']}: {e}")
        return False

    finally:
        del password
        gc.collect()


# ─── Forum Scraping ─────────────────────────────────────────────────────────

def _find_next_page_url(html: str, forum: dict) -> str | None:
    """Extract the 'next page' URL from the current page HTML."""
    soup = BeautifulSoup(html, "html.parser")
    selector = forum["selectors"].get("next_page", "")
    if not selector:
        return None

    next_link = soup.select_one(selector)
    if not next_link:
        return None

    href = next_link.get("href", "")
    if not href:
        return None

    return urljoin(forum["base_url"], href)


def _fetch_page(
    session: requests.Session,
    url: str,
    forum: dict,
    label: str,
) -> str | None:
    """Fetch a single page with delay and error handling. Returns HTML or None."""
    try:
        time.sleep(random.uniform(*INTER_REQUEST_PAUSE))
        session.headers["User-Agent"] = random.choice(USER_AGENTS)
        resp = session.get(url, timeout=REQUEST_TIMEOUT)

        if resp.status_code != 200:
            print_warning(f"[{forum['name']}] HTTP {resp.status_code} — {label}")
            return None

        return resp.text

    except requests.exceptions.ConnectionError:
        print_error(f"[{forum['name']}] Connection failed — forum may be down.")
        return None
    except requests.exceptions.Timeout:
        print_error(f"[{forum['name']}] Request timed out — {label}")
        return None
    except Exception as e:
        print_error(f"[{forum['name']}] Error: {e}")
        return None


def scrape_forum_search(
    session: requests.Session,
    forum: dict,
    query: str,
) -> list[dict]:
    """Search a forum and return matching thread metadata (up to MAX_PAGES pages)."""
    if not forum.get("base_url"):
        return []

    first_url = urljoin(
        forum["base_url"],
        forum["search_path"].format(query=quote(query)),
    )

    all_threads: list[dict] = []
    current_url = first_url
    seen_urls: set[str] = set()

    for page_num in range(1, MAX_PAGES + 1):
        if current_url in seen_urls:
            break  # Loop protection
        seen_urls.add(current_url)

        label = f"search \"{query}\" (page {page_num}/{MAX_PAGES})"
        html = _fetch_page(session, current_url, forum, label)
        if not html:
            break

        threads = parse_thread_listing(html, forum, query)
        if not threads:
            break  # No results on this page — stop

        all_threads.extend(threads)
        print_info(f"[{forum['name']}] Page {page_num}: {len(threads)} threads")

        # Find next page
        if page_num < MAX_PAGES:
            next_url = _find_next_page_url(html, forum)
            if not next_url:
                break  # No more pages
            current_url = next_url

    return all_threads


def scrape_forum_listing(
    session: requests.Session,
    forum: dict,
) -> list[dict]:
    """Scrape the listing page with pagination (up to MAX_PAGES pages)."""
    if not forum.get("base_url") or not forum.get("listing_path"):
        return []

    first_url = urljoin(forum["base_url"], forum["listing_path"])

    all_threads: list[dict] = []
    current_url = first_url
    seen_urls: set[str] = set()

    for page_num in range(1, MAX_PAGES + 1):
        if current_url in seen_urls:
            break
        seen_urls.add(current_url)

        label = f"listing (page {page_num}/{MAX_PAGES})"
        html = _fetch_page(session, current_url, forum, label)
        if not html:
            break

        threads = parse_thread_listing(html, forum)
        if not threads:
            break

        all_threads.extend(threads)
        print_info(f"[{forum['name']}] Listing page {page_num}: {len(threads)} threads")

        # Find next page
        if page_num < MAX_PAGES:
            next_url = _find_next_page_url(html, forum)
            if not next_url:
                break
            current_url = next_url

    return all_threads


def parse_thread_listing(
    html: str,
    forum: dict,
    search_query: str | None = None,
) -> list[dict]:
    """Parse thread listing HTML and extract post metadata."""
    soup = BeautifulSoup(html, "html.parser")
    sel = forum["selectors"]
    threads = []

    rows = soup.select(sel["thread_row"])[:RESULTS_PER_FORUM]

    for row in rows:
        try:
            thread = {"forum": forum["name"]}

            # Title
            title_el = row.select_one(sel["thread_title"])
            if title_el:
                thread["title"] = title_el.get_text(strip=True)
                href = title_el.get("href", "")
                thread["url"] = urljoin(forum["base_url"], href) if href else ""
            else:
                continue  # Skip rows without a title

            # Author
            author_el = row.select_one(sel["thread_author"])
            thread["author"] = author_el.get_text(strip=True) if author_el else "unknown"

            # Date
            date_el = row.select_one(sel["thread_date"])
            if date_el:
                # Try datetime attribute first, then text
                thread["date"] = date_el.get("datetime", date_el.get_text(strip=True))
            else:
                thread["date"] = "N/A"

            # Replies
            replies_el = row.select_one(sel.get("thread_replies", ""))
            thread["replies"] = replies_el.get_text(strip=True) if replies_el else ""

            # Views
            views_el = row.select_one(sel.get("thread_views", ""))
            thread["views"] = views_el.get_text(strip=True) if views_el else ""

            threads.append(thread)

        except Exception:
            continue

    return threads


# ─── Alert Analysis ──────────────────────────────────────────────────────────

def analyze_thread(thread: dict, targets: list[str]) -> dict | None:
    """
    Analyze a thread title against watch targets and breach keywords.
    Returns an enriched alert dict, or None if not relevant.
    """
    title_lower = thread["title"].lower()
    matched_keywords = []
    matched_targets = []

    # Check if title contains any breach-related keywords
    for kw in BREACH_KEYWORDS:
        if kw.lower() in title_lower:
            matched_keywords.append(kw)

    # Check if title mentions any watch targets
    for target in targets:
        if target.lower() in title_lower:
            matched_targets.append(target)

    # If we have targets configured, require at least one target match
    if targets and not matched_targets:
        return None

    # If no targets configured, require at least one keyword match
    if not targets and not matched_keywords:
        return None

    # Determine severity
    severity = _calculate_severity(title_lower, matched_keywords, matched_targets)

    alert = {
        **thread,
        "matched_keywords": matched_keywords,
        "matched_targets": matched_targets,
        "severity": severity,
    }

    return alert


def _calculate_severity(
    title: str,
    keywords: list[str],
    targets: list[str],
) -> str:
    """Estimate alert severity based on content analysis."""
    critical_indicators = [
        "0day", "zero-day", "zeroday",
        "ssn", "social security",
        "credit card", "full db",
        "million", "billion",
        "government", "military",
        "healthcare", "hospital",
        "banking", "financial",
    ]
    high_indicators = [
        "database", "dump", "leak",
        "credentials", "passwords",
        "combolist", "combo list",
        "fresh", "new",
        "employee", "internal",
    ]

    for indicator in critical_indicators:
        if indicator in title:
            return "critical"

    if targets and len(keywords) >= 2:
        return "high"

    for indicator in high_indicators:
        if indicator in title:
            return "high"

    if targets:
        return "medium"

    return "low"


# ─── Deduplication ───────────────────────────────────────────────────────────

class AlertTracker:
    """Track seen alerts to avoid duplicate notifications."""

    def __init__(self, max_history: int = 10000):
        self.seen: set[str] = set()
        self.max_history = max_history

    def fingerprint(self, alert: dict) -> str:
        raw = f"{alert['forum']}:{alert['title'][:120]}:{alert['author']}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_new(self, alert: dict) -> bool:
        fp = self.fingerprint(alert)
        if fp in self.seen:
            return False
        self.seen.add(fp)
        if len(self.seen) > self.max_history:
            to_remove = list(self.seen)[:2000]
            for item in to_remove:
                self.seen.discard(item)
        return True

    def filter_new(self, alerts: list[dict]) -> list[dict]:
        return [a for a in alerts if self.is_new(a)]


# ─── Monitoring Cycle ────────────────────────────────────────────────────────

def build_queries(targets: list[str]) -> list[str]:
    """Build search queries from targets + keywords."""
    queries = []

    # Target-specific queries
    for target in targets:
        # Broad search: just the company name (catches most posts)
        queries.append(target)
        # Specific: company + key breach terms
        for kw in ["database", "leak", "breach", "dump", "credentials"]:
            queries.append(f"{target} {kw}")

    # General queries (always included)
    queries.extend(GENERAL_QUERIES)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for q in queries:
        q_lower = q.lower()
        if q_lower not in seen:
            seen.add(q_lower)
            unique.append(q)

    return unique


def run_monitor_cycle(
    session: requests.Session,
    forums: list[dict],
    targets: list[str],
    tracker: AlertTracker,
    cycle_num: int,
) -> int:
    """Run one full monitoring cycle across all forums."""
    cycle_start = datetime.now()
    all_alerts: list[dict] = []

    print_header(f"🔄 CYCLE #{cycle_num}  —  {cycle_start.strftime('%Y-%m-%d %H:%M:%S')}")

    active_forums = [f for f in forums if f.get("base_url")]
    if not active_forums:
        print_error("No forums configured with valid URLs.")
        print_info("Edit FORUM_DEFINITIONS in the script and add .onion URLs.")
        return 0

    print_info(f"Active forums: {len(active_forums)}")
    print_info(f"Watch targets: {len(targets)} companies")

    queries = build_queries(targets)
    print_info(f"Search queries: {len(queries)}")
    print()

    for forum in active_forums:
        if USE_RICH:
            console.rule(f"[bold magenta]  {forum['name']}  [/]")
        else:
            print(f"\n{'─' * 65}")
            print(f"  {forum['name']}")
            print(f"{'─' * 65}")

        # 1. Scrape the main listing page (databases/leaks section)
        print_info(f"[{forum['name']}] Scanning listing pages (up to {MAX_PAGES})...")
        listing_threads = scrape_forum_listing(session, forum)
        print_info(f"[{forum['name']}] Total: {len(listing_threads)} threads from listing.")

        for thread in listing_threads:
            alert = analyze_thread(thread, targets)
            if alert:
                all_alerts.append(alert)

        # 2. Run search queries
        for query in queries:
            print_info(f"[{forum['name']}] Searching: \"{query}\"")
            search_threads = scrape_forum_search(session, forum, query)

            for thread in search_threads:
                alert = analyze_thread(thread, targets)
                if alert:
                    all_alerts.append(alert)

        print_info(f"[{forum['name']}] Done.")

    # Deduplicate alerts (by title+forum+author)
    unique_alerts = {}
    for alert in all_alerts:
        fp = f"{alert['forum']}:{alert['title'][:120]}:{alert['author']}"
        if fp not in unique_alerts:
            unique_alerts[fp] = alert
    all_alerts = list(unique_alerts.values())

    # Filter to only new alerts
    new_alerts = tracker.filter_new(all_alerts)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    new_alerts.sort(key=lambda a: severity_order.get(a.get("severity", "low"), 3))

    # Display results
    print()
    if new_alerts:
        print_header(f"🚨 {len(new_alerts)} NEW ALERTS — Cycle #{cycle_num}")
        for i, alert in enumerate(new_alerts, 1):
            print_alert(i, alert)
    else:
        print_info("No new alerts in this cycle.")

    # Cycle summary
    elapsed = (datetime.now() - cycle_start).total_seconds()
    print()
    print_header(f"📊 CYCLE #{cycle_num} SUMMARY")
    print_success(f"🚨 New alerts: {len(new_alerts)}")
    print_info(f"📋 Total threads analyzed: {len(all_alerts)}")
    print_info(f"🔍 Forums scanned: {len(active_forums)}")
    print_info(f"⏱️  Cycle duration: {elapsed:.0f}s ({elapsed/60:.1f} min)")
    print_info(f"🗃️  Alerts in history: {len(tracker.seen)}")

    # Renew Tor circuit between cycles for anonymity
    renew_tor_circuit()

    return len(new_alerts)


# ─── Secure Cleanup ─────────────────────────────────────────────────────────

def secure_cleanup(session: requests.Session | None):
    """Clean up session and sensitive data from memory."""
    print_info("🧹 Secure cleanup in progress...")

    if session:
        try:
            session.cookies.clear()
            session.close()
            print_info("   Session closed, cookies cleared.")
        except Exception:
            pass

    gc.collect()
    print_success("🧹 Cleanup complete.")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global MAX_PAGES

    parser = argparse.ArgumentParser(
        description="🔍 DarkScrape — Dark Web Monitor"
    )
    parser.add_argument(
        "--targets",
        nargs="+",
        default=None,
        help="Company names to monitor (overrides WATCH_TARGETS)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=MONITOR_INTERVAL,
        help=f"Seconds between monitoring cycles (default: {MONITOR_INTERVAL})",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (no loop)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=MAX_PAGES,
        help=f"Max pages to scrape per query/listing (default: {MAX_PAGES})",
    )
    parser.add_argument(
        "--setup-creds",
        action="store_true",
        help="Interactive setup: save encrypted forum credentials",
    )
    parser.add_argument(
        "--creds",
        type=str,
        default=CREDENTIALS_FILE,
        help=f"Path to encrypted credentials file (default: {CREDENTIALS_FILE})",
    )
    args = parser.parse_args()

    # Override global pagination setting from CLI
    MAX_PAGES = max(1, min(args.max_pages, 20))  # clamp between 1-20

    # ── Credential setup mode ──
    if args.setup_creds:
        print_header("🔐 Forum Credentials Setup")
        creds = {}
        for forum in FORUM_DEFINITIONS:
            if forum["requires_auth"]:
                print_info(f"\nCredentials for {forum['name']}:")
                username = input(f"  Username (or Enter to skip): ").strip()
                if username:
                    password = getpass.getpass(f"  Password: ")
                    creds[forum["name"]] = {"username": username, "password": password}
                    del password

        if creds:
            save_credentials(creds, args.creds)
        else:
            print_warning("No credentials entered.")
        sys.exit(0)

    # ── Banner ──
    if USE_RICH:
        console.print(Panel(
            "[bold white]🔍 BreachWatch — Dark Web Breach Monitor[/]\n"
            "[dim]Monitoring dark web forums for corporate data breaches[/]\n\n"
            f"[cyan]Mode:[/] {'Single scan' if args.once else 'Continuous monitor'}   "
            f"[cyan]Interval:[/] {args.interval}s   "
            f"[cyan]Pages:[/] {MAX_PAGES}",
            title="[bold red]BreachWatch[/]",
            box=box.DOUBLE,
        ))
    else:
        print_header("🔍 BreachWatch — Dark Web Breach Monitor")

    # ── Determine targets ──
    targets = args.targets if args.targets else WATCH_TARGETS
    if targets:
        print_info(f"Monitoring {len(targets)} targets:")
        for t in targets:
            print_info(f"  • {t}")
    else:
        print_warning("No specific targets configured — running general breach monitoring.")
        print_info("Add targets with: --targets \"Company A\" \"Company B\"")
        print_info("Or edit WATCH_TARGETS in the script.\n")

    # ── Check active forums ──
    active_forums = [f for f in FORUM_DEFINITIONS if f.get("base_url")]
    if not active_forums:
        print_error("No forum URLs configured!")
        print_info("Edit FORUM_DEFINITIONS in the script and add .onion URLs.")
        print_info("Forum URLs change frequently — check current addresses on:")
        print_info("  - darknetlive.com")
        print_info("  - dark.fail")
        sys.exit(1)

    print_info(f"Active forums: {len(active_forums)}")
    print()

    # ── Create Tor session ──
    print_info("Connecting to Tor network...")
    session = create_tor_session()

    if not verify_tor_connection(session):
        print_error("Cannot establish Tor connection. Aborting.")
        print_info("Install Tor: sudo dnf install tor")
        print_info("Start Tor:   sudo systemctl start tor")
        sys.exit(1)

    # ── Load forum credentials ──
    if os.path.isfile(args.creds):
        print_info("Loading forum credentials...")
        creds = load_credentials(args.creds)
        # Log in to each forum
        for forum in active_forums:
            if forum["name"] in creds:
                c = creds[forum["name"]]
                login_to_forum(session, forum, c["username"], c["password"])
                del c
        del creds
        gc.collect()
    else:
        print_warning("No credentials file found — searching without authentication.")
        print_info(f"To set up credentials: python {sys.argv[0]} --setup-creds\n")

    # ── Signal handlers ──
    def _signal_handler(signum, frame):
        print_warning("\n\n🛑 Signal received, cleaning up...")
        secure_cleanup(session)
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ── Run ──
    tracker = AlertTracker()

    try:
        if args.once:
            # Single scan
            run_monitor_cycle(session, FORUM_DEFINITIONS, targets, tracker, 1)
        else:
            # Continuous monitoring loop
            cycle = 0
            print_success("Monitor started. Press Ctrl+C to stop.\n")

            while True:
                cycle += 1
                try:
                    run_monitor_cycle(session, FORUM_DEFINITIONS, targets, tracker, cycle)
                except Exception as e:
                    print_error(f"Error in cycle #{cycle}: {e}")
                    print_info("Retrying next cycle...")

                mins = args.interval // 60
                secs = args.interval % 60
                print_info(
                    f"⏳ Next cycle in {mins}m {secs}s... Ctrl+C to stop."
                )
                time.sleep(args.interval)

    except KeyboardInterrupt:
        print_warning("\n\n🛑 Monitor stopped by user.")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
    finally:
        secure_cleanup(session)


if __name__ == "__main__":
    main()
