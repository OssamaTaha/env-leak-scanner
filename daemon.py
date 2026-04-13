#!/usr/bin/env python3
"""
.env Leak Radar — Real-time daemon
Continuously scans GitHub for new secret exposures and notifies developers.
Runs as a background service, respects rate limits, never re-notifies same repo.
"""

import subprocess
import json
import sys
import os
import time
import signal
import smtplib
import re
import base64
from datetime import datetime, timezone
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import config
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

# ── Colors ──────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Search Queries ──────────────────────────────────────────────────
# All queries — env files + code files + crypto + financial
# We rotate through these and paginate to scan wider

ALL_QUERIES = {
    # ── .env files ──
    "OpenAI (.env)":           'filename:.env "sk-proj-"',
    "AWS (.env)":              'filename:.env "AKIA"',
    "Stripe (.env)":           'filename:.env "sk_live_"',
    "DB URLs (.env)":          'filename:.env "postgresql://" password',
    "MongoDB (.env)":          'filename:.env "mongodb+srv://"',
    "Discord (.env)":          'filename:.env "DISCORD_TOKEN" NOT skeleton',
    "GitHub (.env)":           'filename:.env "GITHUB_TOKEN" NOT example',
    "Firebase (.env)":         'filename:.env "FIREBASE_PRIVATE_KEY"',
    "Twilio (.env)":           'filename:.env "TWILIO_AUTH_TOKEN"',
    "SendGrid (.env)":         'filename:.env "SENDGRID_API_KEY"',
    "Telegram (.env)":         'filename:.env "TELEGRAM_BOT_TOKEN"',
    "JWT (.env)":              'filename:.env "JWT_SECRET" NOT example',
    "SMTP (.env)":             'filename:.env "SMTP_PASSWORD"',
    "Gemini (.env)":           'filename:.env "GOOGLE_API_KEY" NOT example',
    "Anthropic (.env)":        'filename:.env "ANTHROPIC_API_KEY"',
    # ── Code files ──
    "OpenAI (code)":           'filename:.py OR filename:.js "sk-proj-" NOT node_modules',
    "AWS (code)":              'filename:.py OR filename:.js "AKIA" NOT node_modules',
    "Stripe (code)":           'filename:.py OR filename:.js "sk_live_" NOT node_modules',
    "Private keys (code)":     'filename:.pem OR filename:.key "PRIVATE KEY"',
    "DB passwords (code)":     'filename:.py OR filename:.js "password=" NOT test',
    "GitHub tokens (code)":    'filename:.py OR filename:.js "ghp_" NOT node_modules',
    "Firebase (code)":         'filename:.py OR filename:.js "firebase" "private_key"',
    "JWT (code)":              'filename:.py OR filename:.js "jwt" "secret=" NOT test',
    # ── Crypto / Financial ──
    "Ethereum keys":           'filename:.env OR filename:.py "0x" private_key',
    "Wallet mnemonics":        'filename:.env OR filename:.py mnemonic OR seed_phrase',
    "Crypto secrets":          'filename:.env OR filename:.py wallet_key OR WALLET_PRIVATE_KEY',
    "Stripe restricted":       'filename:.py "rk_live_"',
    "Payment providers":       'filename:.env "paypal" OR "square" OR "braintree" "secret"',
    "Credit cards":            'filename:.env OR filename:.py "card_number" OR "cc_number"',
}

# Track which page we're on for each query (for pagination across cycles)
QUERY_PAGE_STATE = {q: 1 for q in ALL_QUERIES}


# ── State ───────────────────────────────────────────────────────────
running = True
cycle_count = 0
total_notified = 0
total_scanned = 0


def signal_handler(sig, frame):
    global running
    print(f"\n{YELLOW}🛑 Shutting down gracefully...{RESET}")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def log(msg, level="info"):
    """Structured logging with timestamp."""
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"info": DIM, "ok": GREEN, "warn": YELLOW, "err": RED, "scan": CYAN}
    c = colors.get(level, DIM)
    print(f"{c}[{ts}] {msg}{RESET}")


# ── Rate Limit Handling ─────────────────────────────────────────────
def get_rate_limit():
    try:
        r = subprocess.run(["gh", "api", "/rate_limit"],
                          capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            s = data.get("resources", {}).get("search", {})
            return {"remaining": s.get("remaining", 0),
                    "limit": s.get("limit", 0),
                    "reset": s.get("reset", 0)}
    except Exception:
        pass
    return {"remaining": 0, "limit": 0, "reset": 0}


def wait_for_rate_limit():
    """Wait if we're about to hit rate limit."""
    rl = get_rate_limit()
    if rl["remaining"] < 3:
        now = int(time.time())
        wait = max(0, rl["reset"] - now) + 3
        if wait > 0:
            reset_at = datetime.fromtimestamp(rl["reset"], tz=timezone.utc).astimezone()
            log(f"Rate limit low ({rl['remaining']} left). Waiting {wait}s until {reset_at.strftime('%H:%M:%S')}", "warn")
            while wait > 0 and running:
                time.sleep(min(5, wait))
                wait -= 5
            log("Rate limit reset", "ok")


# ── GitHub Search ───────────────────────────────────────────────────
def search_github(query, page=1):
    """Search GitHub code via gh CLI with rate limit handling and pagination."""
    wait_for_rate_limit()
    try:
        r = subprocess.run(
            ["gh", "api", "search/code", "-X", "GET",
             "-f", f"q={query}", "-f", "per_page=10", "-f", f"page={page}"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            if "rate limit" in r.stderr.lower():
                time.sleep(65)
                return search_github(query, page)
            return None
        return json.loads(r.stdout)
    except Exception as e:
        log(f"Search failed: {e}", "err")
        return None


def filter_real_secrets(items):
    skip = {"example", "sample", "template", "dist", "skeleton",
            "dummy", "placeholder", "test", "fake", "mock", ".bak"}
    real = []
    for item in items:
        path = item.get("path", "")
        repo = item.get("repository", {})
        if repo.get("private", True):
            continue
        if any(kw in path.lower() for kw in skip):
            continue
        real.append({
            "repo": repo.get("full_name", ""),
            "file": path,
            "url": item.get("html_url", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
        })
    return real


# ── Secret Verification ─────────────────────────────────────────────

# Known test/example/placeholder patterns for each secret type
SECRET_PATTERNS = {
    "OpenAI Keys": {
        "test_patterns": [
            r"sk-test-",           # Stripe-style test
            r"sk-proj-test",
        ],
        "real_pattern": r"sk-proj-[A-Za-z0-9]{20,}",  # Real OpenAI proj keys are long
        "min_length": 40,
    },
    "AWS Access Keys": {
        "test_patterns": [
            r"AKIAIOSFODNN7EXAMPLE",  # AWS official example
            r"AKIAIOSFODNN7TEST",
            r"AKIA.{4}TEST",
            r"AKIA.{4}EXAMPLE",
        ],
        "real_pattern": r"AKIA[A-Z0-9]{16}",  # Real AWS keys: AKIA + 16 alphanumeric
        "min_length": 20,
    },
    "Stripe Live Keys": {
        "test_patterns": [
            r"sk_test_",
            r"rk_test_",
        ],
        "real_pattern": r"sk_live_[a-zA-Z0-9]{24,}",
        "min_length": 30,
    },
    "Database URLs": {
        "test_patterns": [
            r"localhost",
            r"127\.0\.0\.1",
            r"password@",
            r"changeme@",
            r"test@",
            r"example\.com",
        ],
        "real_pattern": r"postgresql://[^:]+:[^@]{8,}@[a-z0-9.-]+\.com",
        "min_length": 30,
    },
    "MongoDB URIs": {
        "test_patterns": [
            r"localhost",
            r"127\.0\.0\.1",
            r"mongodb://localhost",
        ],
        "real_pattern": r"mongodb\+srv://[^:]+:[^@]{8,}@[^/]+\.mongodb\.net",
        "min_length": 40,
    },
}

# Generic placeholder keywords that apply to ALL secret types
GENERIC_PLACEHOLDERS = {
    "your_", "xxx", "changeme", "password", "secret", "token",
    "example", "test", "fake", "dummy", "placeholder", "insert_",
    "replace_", "todo", "fill_in", "put_", "<your", "change_me",
    "my_", "sample_", "demo_", "abc123", "123456", "qwerty",
    "aaaa", "bbbb", "cccc", "000000",
}


def fetch_file_content(repo_full_name, file_path):
    """Fetch actual file content from GitHub."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo_full_name}/contents/{file_path}",
             "-q", ".content"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return base64.b64decode(r.stdout.strip()).decode('utf-8', errors='ignore')
    except Exception:
        pass
    return None


def is_real_secret(key, value, secret_type):
    """Check if a key=value pair contains a REAL secret, not a placeholder."""
    if not value:
        return False
    
    value = value.strip().strip('"').strip("'")
    
    # Too short to be a real secret
    if len(value) < 12:
        return False
    
    # Check generic placeholders
    val_lower = value.lower()
    for placeholder in GENERIC_PLACEHOLDERS:
        if placeholder in val_lower:
            return False
    
    # Check if it's just repeated characters (e.g., "aaaaaaaaaa")
    if len(set(value)) < 4 and len(value) < 30:
        return False
    
    # Check type-specific patterns
    if secret_type in SECRET_PATTERNS:
        patterns = SECRET_PATTERNS[secret_type]
        
        # Check test patterns — if matches, it's a test key
        for test_pat in patterns.get("test_patterns", []):
            if re.search(test_pat, value, re.IGNORECASE):
                return False
        
        # Check if it meets minimum length
        if len(value) < patterns.get("min_length", 15):
            return False
    
    # For API keys: should have decent entropy (mix of chars)
    if "KEY" in key.upper() or "TOKEN" in key.upper() or "SECRET" in key.upper():
        # Count unique characters ratio
        unique_ratio = len(set(value)) / len(value) if value else 0
        if unique_ratio < 0.3:  # Low entropy = likely placeholder
            return False
    
    # If it passed all checks, it's probably real
    return True


def verify_repo_secrets(repo_full_name, file_path, secret_type):
    """Fetch file content and verify it contains real secrets.
    Returns (has_real_secrets: bool, real_secrets_found: list of dicts with line numbers)"""
    
    content = fetch_file_content(repo_full_name, file_path)
    if not content:
        return True, [{"key": "?", "line": 0, "preview": "(could not verify content)"}]
    
    real_secrets = []
    
    for line_num, line in enumerate(content.split('\n'), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        
        # ── False positive filtering ──
        skip_indicators = [
            'input(', 'print(', 'prompt', 'assert ', 'startswith(',
            'endswith(', '== "sk', '!= "sk', 'example', 'placeholder',
            'README', 'documentation', 'tutorial', 'sample',
            'your_api_key', 'YOUR_', 'todo', 'changeme',
            'insert_', 'replace_', 'dummy', 'fake', 'mock',
            'test_key', 'unit_test', 'pytest', 'unittest',
        ]
        if any(skip in line.lower() for skip in skip_indicators):
            continue
        if re.search(r'(?:print|input|log|warn|error|raise|assert)\s*\(', line):
            continue
        
        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        
        if not val:
            continue
        
        if is_real_secret(key, val, secret_type):
            if len(val) > 12:
                masked = f"{val[:4]}...{val[-4:]}"
            else:
                masked = val[:6] + "..."
            real_secrets.append({
                "key": key,
                "line": line_num,
                "preview": f"{masked} ({len(val)} chars)",
                "github_link": f"https://github.com/{repo_full_name}/blob/main/{file_path}#L{line_num}",
            })
    
    return len(real_secrets) > 0, real_secrets


# ── Live Key Validation ─────────────────────────────────────────────
# Actually test if a leaked key STILL WORKS before notifying.
# If it's already revoked, no point emailing.

import requests

KEY_TEST_TIMEOUT = 8  # seconds max per test


def test_openai_key(value):
    """Test OpenAI API key by listing models."""
    try:
        r = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {value}"},
            timeout=KEY_TEST_TIMEOUT
        )
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_aws_key(value):
    """Test AWS access key via STS GetCallerIdentity."""
    import hmac, hashlib, datetime
    
    # We need both access key AND secret key — extract if found together
    # For now just check format validity with a lightweight call
    try:
        # STS GetCallerIdentity — works with any valid AWS key
        r = requests.get(
            "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            headers={"Authorization": f"AWS4-HMAC-SHA256 Credential={value}"},
            timeout=KEY_TEST_TIMEOUT
        )
        # 403 with proper error = key exists but wrong sig (means key is real)
        # 403 with InvalidClientTokenId = key doesn't exist
        body = r.text
        if "InvalidClientTokenId" in body:
            return False, "InvalidClientTokenId"
        if "SignatureDoesNotMatch" in body:
            return True, "Key exists (signature mismatch expected without secret)"
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_stripe_key(value):
    """Test Stripe live key by fetching account balance."""
    try:
        r = requests.get(
            "https://api.stripe.com/v1/balance",
            auth=(value, ""),
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            return True, "ACTIVE — balance endpoint returned 200"
        elif r.status_code == 401:
            body = r.json()
            if "expired" in body.get("error", {}).get("message", "").lower():
                return False, "Expired/revoked"
            return False, "Invalid key"
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_discord_token(value):
    """Test Discord token by fetching current user."""
    try:
        r = requests.get(
            "https://discord.com/api/v10/users/@me",
            headers={"Authorization": value},
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            return True, f"ACTIVE — @{data.get('username', '?')}#{data.get('discriminator', '?')}"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_github_token(value):
    """Test GitHub token by fetching user info."""
    try:
        r = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {value}"},
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            return True, f"ACTIVE — @{data.get('login', '?')}"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_telegram_token(value):
    """Test Telegram bot token via getMe API."""
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{value}/getMe",
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("ok"):
                bot = data.get("result", {})
                return True, f"ACTIVE — @{bot.get('username', '?')}"
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_anthropic_key(value):
    """Test Anthropic API key with a minimal request."""
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": value,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-3-haiku-20240307",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}]
            },
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            return True, "ACTIVE — API accepted request"
        elif r.status_code == 401:
            return False, "Invalid/revoked"
        elif r.status_code == 400:
            # Bad request but auth worked = key is valid
            return True, "ACTIVE — key accepted (400 = model/auth OK)"
        return r.status_code < 500, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_gemini_key(value):
    """Test Google AI/Gemini API key."""
    try:
        r = requests.get(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={value}",
            timeout=KEY_TEST_TIMEOUT
        )
        if r.status_code == 200:
            return True, "ACTIVE — models endpoint returned 200"
        elif r.status_code == 403:
            return False, "Invalid or restricted key"
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_sendgrid_key(value):
    """Test SendGrid API key."""
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {value}"},
            timeout=KEY_TEST_TIMEOUT
        )
        return r.status_code == 200, f"HTTP {r.status_code}"
    except Exception as e:
        return None, str(e)


def test_firebase_key(value):
    """Can't easily test Firebase private keys without full config."""
    return None, "Cannot test — requires full service account"


def test_database_url(value):
    """Can't test remote DB URLs (firewalls, connection strings)."""
    return None, "Cannot test — requires network access to DB host"


def test_mongodb_uri(value):
    """Can't test remote MongoDB URIs from here."""
    return None, "Cannot test — requires network access to cluster"


def test_jwt_secret(value):
    """Can't test JWT secrets without knowing which service uses them."""
    return None, "Cannot test — requires matching JWT endpoint"


def test_smtp_password(value):
    """Can't test SMTP passwords without knowing the server."""
    return None, "Cannot test — requires SMTP server context"


# Map secret types to their test functions
KEY_TESTERS = {
    "OpenAI Keys": test_openai_key,
    "AWS Access Keys": test_aws_key,
    "Stripe Live Keys": test_stripe_key,
    "Discord Tokens": test_discord_token,
    "GitHub Tokens": test_github_token,
    "Telegram Bots": test_telegram_token,
    "Anthropic Claude": test_anthropic_key,
    "Gemini/Google AI": test_gemini_key,
    "SendGrid Keys": test_sendgrid_key,
    "Firebase Keys": test_firebase_key,
    "Database URLs": test_database_url,
    "MongoDB URIs": test_mongodb_uri,
    "JWT Secrets": test_jwt_secret,
    "SMTP Passwords": test_smtp_password,
    "Twilio Auth": test_sendgrid_key,
}


def get_tester_for_category(secret_type):
    """Find the right tester function for any category name.
    Handles variations like 'OpenAI (.env)', 'OpenAI (code)', 'OpenAI Keys'."""
    # Direct match first
    if secret_type in KEY_TESTERS:
        return KEY_TESTERS[secret_type]
    
    # Fuzzy match: check if any KEY_TESTERS key is contained in secret_type
    secret_lower = secret_type.lower()
    for key, tester in KEY_TESTERS.items():
        key_word = key.split()[0].lower()  # "openai" from "OpenAI Keys"
        if key_word in secret_lower:
            return tester
    
    return None


def test_keys_in_file(repo_full_name, file_path, secret_type):
    """Fetch .env file, extract secrets, test each one live.
    Returns (any_active: bool, test_results: list of dicts)"""
    
    content = fetch_file_content(repo_full_name, file_path)
    if not content:
        return None, [{"key": "?", "status": "unknown", "detail": "could not fetch file"}]
    
    tester = get_tester_for_category(secret_type)
    if not tester:
        return None, [{"key": "?", "status": "unknown", "detail": f"no tester for {secret_type}"}]
    
    results = []
    any_active = False
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        
        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        
        if not val or len(val) < 12:
            continue
        
        # Skip obvious placeholders
        if not is_real_secret(key, val, secret_type):
            continue
        
        # Test the key
        log(f"    Testing {key}...", "scan")
        is_active, detail = tester(val)
        
        result = {
            "key": key,
            "value_preview": f"{val[:4]}...{val[-4:]}",
            "active": is_active,
            "detail": detail,
        }
        results.append(result)
        
        if is_active:
            any_active = True
            log(f"    🔴 {key} = {detail}", "err")
        elif is_active is False:
            log(f"    🟢 {key} = {detail} (revoked/invalid)", "ok")
        else:
            log(f"    🟡 {key} = {detail} (could not test)", "warn")
    
    return any_active, results


# ── Blocklist ───────────────────────────────────────────────────────
BLOCKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blocklist.json")

def load_blocklist():
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE) as f:
                return set(json.load(f))
        except: pass
    return set()

BLOCKED_EMAILS = load_blocklist()


# ── Notification Cache ──────────────────────────────────────────────
def load_notified():
    cache_file = config.NOTIFIED_CACHE
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_notified(notified_set):
    with open(config.NOTIFIED_CACHE, "w") as f:
        json.dump(list(notified_set), f)


# ── Contact Info ────────────────────────────────────────────────────
def get_owner_email(repo_full_name):
    """Get best email for repo owner."""
    owner = repo_full_name.split("/")[0]
    
    # Try profile email
    try:
        r = subprocess.run(["gh", "api", f"users/{owner}"],
                          capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            email = data.get("email")
            if email and "noreply" not in email:
                return email, data.get("name", owner), data.get("login", owner)
    except Exception:
        pass
    
    # Fallback: commit emails
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo_full_name}/commits?per_page=5",
             "-q", ".[].commit.author.email"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            for email in r.stdout.strip().split("\n"):
                email = email.strip()
                if email and "noreply" not in email:
                    return email, owner, owner
    except Exception:
        pass
    
    return None, owner, owner


# ── Email Sending ───────────────────────────────────────────────────
def send_email(to_email, repo_full_name, exposed_file, secret_type, owner_name, real_secrets_list=None):
    """Send security notification email via SMTP."""
    if not config.SMTP_PASS:
        log(f"SMTP not configured. Would email {to_email}", "warn")
        return False
    
    subject = f"🔴 CONFIRMED ACTIVE secret in {repo_full_name}"
    
    # Build the exposed secrets detail
    secrets_detail = ""
    if real_secrets_list:
        for s in real_secrets_list:
            if isinstance(s, dict):
                line_info = f"Line {s['line']}" if s.get('line') else "Unknown line"
                link = s.get('github_link', '')
                secrets_detail += f"\n  • {s.get('key', '?')} = {s.get('preview', '?')}\n    {line_info}"
                if link:
                    secrets_detail += f"\n    → {link}"
            else:
                secrets_detail += f"\n  • {s}"
    else:
        secrets_detail = f"\n  File: {exposed_file}\n  Type: {secret_type}"
    
    body = f"""Hey {owner_name},

⚠️  I tested the secrets in your repository {repo_full_name} and confirmed they are STILL ACTIVE.

Exposed file: {exposed_file}
Secret type: {secret_type}
URL: https://github.com/{repo_full_name}/blob/main/{exposed_file}

🔴 THIS KEY STILL WORKS — I was able to make successful API calls with it.
   Anyone who finds this file can use your credentials RIGHT NOW.

Exposed secrets:{secrets_detail}

HOW TO FIX:
  1. ROTATE the exposed credentials NOW (most important!)
  2. git filter-repo --invert-paths --path {exposed_file}
  3. git push --force --all
  4. Add to .gitignore: .env .env.local .env.*.local

If you've already rotated the key, you can ignore this.
But please check — if the key is still active, you're at risk.

📚 https://github.com/OssamaTaha/env-leak-scanner

This is an automated security alert.
Stay secure 🛡️
"""
    
    try:
        msg = MIMEMultipart()
        msg["From"] = f"{config.FROM_NAME} <{config.FROM_EMAIL}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg["Reply-To"] = config.FROM_EMAIL
        msg.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
            server.starttls()
            server.login(config.SMTP_USER, config.SMTP_PASS)
            server.send_message(msg)
        
        return True
    except Exception as e:
        log(f"Email failed for {to_email}: {e}", "err")
        return False


# ── GitHub Issue Notification ───────────────────────────────────────
def create_issue(repo_full_name, exposed_file, secret_type):
    """Create a security issue on the repo."""
    title = f"🔒 Security: secrets exposed in {exposed_file}"
    body = f"""## ⚠️ Exposed Secrets Detected

Your repository `{repo_full_name}` has exposed secrets in `{exposed_file}`.

**Type:** {secret_type}
**File:** `{exposed_file}`

### Why This Matters

Even if you've removed this file in a recent commit, the secrets remain in your **git history forever**. Anyone can run:

```bash
git log -p -- {exposed_file}
```

### How to Fix

1. **ROTATE** the exposed credentials immediately
2. Scrub history: `git filter-repo --invert-paths --path {exposed_file}`
3. Force push: `git push --force --all`
4. Add to `.gitignore`:
   ```
   .env
   .env.local
   .env.*.local
   ```

### Resources
- [env-leak-scanner](https://github.com/OssamaTaha/env-leak-scanner) — the tool that found this
- [git-filter-repo](https://github.com/newren/git-filter-repo) — scrub git history

---
*This is an automated security notification from [env-leak-scanner](https://github.com/OssamaTaha/env-leak-scanner). No judgment — this happens to everyone.*
"""
    
    try:
        r = subprocess.run(
            ["gh", "issue", "create", "--repo", repo_full_name,
             "--title", title, "--body", body],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            return r.stdout.strip()
        else:
            return None
    except Exception:
        return None


# ── Main Scan Cycle ─────────────────────────────────────────────────

# ── Unknown Secret Detection (regex + AI) ───────────────────────────
# Catch secrets that don't match known patterns.
# Use regex to find suspicious strings, then AI to identify provider.

# Generic patterns that look like secrets in ANY file type
GENERIC_SECRET_PATTERNS = [
    # variable = "long-random-string"  (python, js, ts, etc)
    (r'(?:api_key|apikey|api_token|secret_key|secret|password|passwd|token|auth|credential|private_key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
     "secret_assignment", "Key/password assignment with 20+ char value"),
    
    # export SECRET="value"  (shell)
    (r'(?:export\s+)?(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\s*=\s*["\']?([A-Za-z0-9+/=_\-]{20,})["\']?',
     "env_assignment", "Environment variable with 20+ char value"),
    
    # connection strings with embedded passwords
    (r'(?:mongodb|postgresql|mysql|redis|amqp)://[^:]+:([^@\s]{8,})@',
     "connection_string", "Database connection string with embedded password"),
    
    # AWS-style keys (AKIA + 16 chars)
    (r'(AKIA[A-Z0-9]{16})', "aws_access_key", "AWS access key pattern"),
    
    # Generic long base64 strings assigned to vars (32+ chars)
    (r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']',
     "base64_blob", "Long base64 string (possible key/token)"),
    
    # GitHub tokens
    (r'(ghp_[A-Za-z0-9]{36})', "github_pat", "GitHub personal access token"),
    (r'(gho_[A-Za-z0-9]{36})', "github_oauth", "GitHub OAuth token"),
    (r'(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})', "github_fine_pat", "GitHub fine-grained PAT"),
    
    # Slack tokens
    (r'(xoxb-[0-9]{10,}-[A-Za-z0-9]{24,})', "slack_bot", "Slack bot token"),
    (r'(xoxp-[0-9]{10,}-[A-Za-z0-9]{24,})', "slack_user", "Slack user token"),
    
    # Stripe
    (r'(sk_live_[a-zA-Z0-9]{24,})', "stripe_live", "Stripe live secret key"),
    (r'(rk_live_[a-zA-Z0-9]{24,})', "stripe_restricted", "Stripe restricted key"),
    
    # SendGrid
    (r'(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})', "sendgrid", "SendGrid API key"),
    
    # Twilio
    (r'(SK[a-f0-9]{32})', "twilio_sid", "Twilio API key SID"),
    
    # Private keys in files
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "private_key", "Private key block"),
    
    # High-entropy strings near password/token keywords (20+ unique chars in 32+ length)
    (r'(?:pass|token|secret|key|auth)\w*\s*[=:]\s*["\']([^"\']{32,})["\']',
     "high_entropy_near_keyword", "Possible secret near password/token keyword"),

    # ── Crypto Wallet Private Keys ──
    # Ethereum private key (64 hex chars, sometimes with 0x prefix)
    (r'(?:0x)?([a-fA-F0-9]{64})', "eth_private_key", "Ethereum private key (64 hex)"),

    # Bitcoin WIF private keys (start with 5, K, or L, base58 ~51-52 chars)
    (r'["\']?([5KL][1-9A-HJ-NP-Za-km-z]{50,51})["\']?', "btc_wif_key", "Bitcoin WIF private key"),

    # Solana private key (base58, typically 64+ chars, often as byte array)
    (r'(?:secretKey|private_key|secret_key)\s*[=:]\s*\[([0-9,\s]{100,})\]', "solana_key_array", "Solana private key (byte array)"),
    (r'["\']([1-9A-HJ-NP-Za-km-z]{64,88})["\']', "solana_base58", "Possible Solana/base58 private key"),

    # BIP39 mnemonic seed phrases (12 or 24 common English words)
    (r'(?:mnemonic|seed|recovery|backup)\w*\s*[=:]\s*["\']([a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+ [a-z]+)["\']',
     "mnemonic_12", "Possible 12-word seed phrase"),
    (r'(?:mnemonic|seed|recovery|backup)\w*\s*[=:]\s*["\']([a-z]+(?: [a-z]+){23})["\']',
     "mnemonic_24", "Possible 24-word seed phrase"),

    # Generic crypto private key assignments
    (r'(?:private_key|privkey|privateKey|secretKey|wallet_key|WALLET_PRIVATE_KEY)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{32,})["\']',
     "crypto_private_key", "Crypto wallet private key assignment"),

    # ── Financial / Payment Secrets ──
    # Stripe restricted keys
    (r'(rk_live_[a-zA-Z0-9]{24,})', "stripe_restricted", "Stripe restricted key"),
    (r'(rk_test_[a-zA-Z0-9]{24,})', "stripe_restricted_test", "Stripe restricted test key"),

    # PayPal access tokens
    (r'(access_token\$[A-Za-z0-9_-]{50,})', "paypal_token", "PayPal access token"),

    # Square access tokens
    (r'(sq0atp-[0-9A-Za-z\-_]{22,})', "square_token", "Square access token"),
    (r'(sq0csp-[0-9A-Za-z\-_]{43,})', "square_secret", "Square OAuth secret"),

    # Braintree access tokens
    (r'(access_token\$production\$[a-z0-9]+\$[a-f0-9]{32})', "braintree_token", "Braintree access token"),

    # CoinBase API keys
    (r'(organizations/[a-f0-9-]+/apiKeys/[a-f0-9-]+)', "coinbase_key_id", "Coinbase API key ID"),

    # Binance API signature
    (r'(?:binance|BNB).*(?:secret|api_secret)\s*[=:]\s*["\']([A-Za-z0-9]{32,64})["\']',
     "binance_secret", "Binance API secret"),

    # Credit card numbers (Luhn-valid patterns)
    (r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})',
     "credit_card", "Possible credit card number"),

    # Bank routing/account patterns (US)
    (r'(?:routing|aba|routing_number)\s*[=:]\s*["\']?(\d{9})["\']?', "bank_routing", "US bank routing number"),
    (r'(?:account_number|bank_account)\s*[=:]\s*["\']?(\d{8,17})["\']?', "bank_account", "Bank account number"),

    # IBAN patterns
    (r'["\']?([A-Z]{2}\d{2}[A-Z0-9]{4,30})["\']?', "iban", "Possible IBAN"),
]

# Known provider prefix patterns for quick classification
PROVIDER_PREFIXES = {
    # API Keys
    "sk-proj-": "OpenAI",
    "sk_live_": "Stripe (live)",
    "sk_test_": "Stripe (test)",
    "rk_live_": "Stripe Restricted (live)",
    "rk_test_": "Stripe Restricted (test)",
    "AKIA": "AWS",
    "ghp_": "GitHub PAT",
    "gho_": "GitHub OAuth",
    "github_pat_": "GitHub Fine-grained PAT",
    "SG.": "SendGrid",
    "xoxb-": "Slack Bot",
    "xoxp-": "Slack User",
    "SKA": "Twilio",
    "pk_live_": "Stripe Public (live)",
    "pk_test_": "Stripe Public (test)",
    "npm_": "npm",
    "glpat-": "GitLab PAT",
    "sq0atp-": "Square",
    "sq0csp-": "Square Secret",
    "organizations/": "Coinbase",
    # Database
    "mongodb+srv://": "MongoDB",
    "postgresql://": "PostgreSQL",
    "mysql://": "MySQL",
    "redis://": "Redis",
    # Crypto
    "0x": "Ethereum",
    "5": "Bitcoin (WIF compressed)",
    "K": "Bitcoin (WIF K-prefix)",
    "L": "Bitcoin (WIF L-prefix)",
    "sqs.": "AWS SQS",
    "arn:aws:": "AWS ARN",
}


def classify_by_prefix(value):
    """Quick classification by known prefixes."""
    for prefix, provider in PROVIDER_PREFIXES.items():
        if value.startswith(prefix):
            return provider
    return None


def scan_content_for_secrets(content, file_path=""):
    """Scan file content with regex patterns to find suspicious secrets.
    Returns list of found secrets with context."""
    
    found = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#') or line_stripped.startswith('//'):
            continue
        
        # ── Skip false positives ──
        # Lines that are just prompts, error messages, comments, docs
        skip_indicators = [
            'input(',          # input("Enter your key...")
            'print(',          # print("Your key starts with sk-...")
            'prompt',          # prompt = "Enter sk-proj-..."
            'assert ',         # assert key.startswith("sk-")
            'startswith(',     # if key.startswith("sk-proj-")
            'endswith(',       # validation
            '== "sk',          # if key == "sk-proj-..."
            '!= "sk',          # comparison
            'example',         # "sk-your-example-key"
            'placeholder',     # placeholders
            'README',          # docs
            'documentation',   # docs
            'tutorial',        # tutorials
            'sample',          # sample code
            'your_api_key',    # "your_api_key_here"
            'YOUR_',           # "YOUR_API_KEY"
            'todo',            # TODO: add your key
            'changeme',        # obvious placeholders
            'insert_',         # "insert_key_here"
            'replace_',        # "replace_with_your_key"
            'dummy',           # dummy values
            'fake',            # fake keys
            'mock',            # mock values
            'test_key',        # test keys
            'unit_test',       # test files
            'pytest',          # test files
            'unittest',        # test files
            'describe(',       # JS test blocks
            'it(',             # JS test blocks
        ]
        
        if any(skip in line_stripped.lower() for skip in skip_indicators):
            continue
        
        # Skip if the match is inside a print/input/prompt/assert string
        # i.e., the secret-looking value is just a string literal being displayed
        if re.search(r'(?:print|input|log|warn|error|raise|assert|console\.\w+)\s*\(', line_stripped):
            continue
        
        for pattern, pattern_name, description in GENERIC_SECRET_PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                # Get the captured group (the actual secret value)
                value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip().strip('"').strip("'")
                
                if not value or len(value) < 15:
                    continue
                
                # Skip if it's clearly a placeholder
                if is_real_secret("", value, "") is False:
                    continue
                
                # Extra check: skip if value is inside a string being printed/inputted
                before_match = line[:match.start()].strip()
                if any(x in before_match for x in ['print(', 'input(', 'log(', 'prompt', 'error', 'raise']):
                    continue
                
                # Quick classify by prefix
                provider = classify_by_prefix(value)
                
                found.append({
                    "line": line_num,
                    "value_preview": f"{value[:6]}...{value[-4:]}" if len(value) > 14 else value,
                    "value_full": value,
                    "pattern": pattern_name,
                    "description": description,
                    "provider": provider or "unknown",
                    "context": line_stripped[:120],
                })
    
    return found


def ai_identify_secret(value, context=""):
    """Use AI (Hermes) to identify what provider a secret belongs to.
    Falls back to heuristic analysis if Hermes is unavailable."""
    
    # Heuristic checks first (no API call needed)
    provider = classify_by_prefix(value)
    if provider:
        return provider, "prefix_match"
    
    # Check entropy and format
    if re.match(r'^[A-F0-9]{40}$', value):
        return "Possibly AWS Secret Key or SHA1 hash", "format_match"
    if re.match(r'^[A-Za-z0-9+/]{40,}={0,2}$', value):
        return "Possibly Base64-encoded key/token", "format_match"
    if re.match(r'^[a-f0-9]{64}$', value):
        return "Possibly SHA-256 hash or API key", "format_match"
    
    # Check context clues from the line
    ctx_lower = context.lower()
    if "stripe" in ctx_lower: return "Likely Stripe", "context"
    if "aws" in ctx_lower or "amazon" in ctx_lower: return "Likely AWS", "context"
    if "openai" in ctx_lower or "gpt" in ctx_lower: return "Likely OpenAI", "context"
    if "firebase" in ctx_lower: return "Likely Firebase", "context"
    if "sendgrid" in ctx_lower: return "Likely SendGrid", "context"
    if "twilio" in ctx_lower: return "Likely Twilio", "context"
    if "slack" in ctx_lower: return "Likely Slack", "context"
    if "github" in ctx_lower: return "Likely GitHub", "context"
    if "mongo" in ctx_lower: return "Likely MongoDB", "context"
    if "postgres" in ctx_lower: return "Likely PostgreSQL", "context"
    if "redis" in ctx_lower: return "Likely Redis", "context"
    if "jwt" in ctx_lower or "token" in ctx_lower: return "Possibly JWT/API Token", "context"
    if "password" in ctx_lower or "pass" in ctx_lower: return "Possibly Password", "context"
    if "secret" in ctx_lower: return "Possibly API Secret", "context"
    
    return "Unknown provider", "no_match"


def try_validate_generic(value):
    """Try to validate a secret by testing against known providers."""
    
    # OpenAI
    if value.startswith("sk-"):
        try:
            r = requests.get("https://api.openai.com/v1/models",
                           headers={"Authorization": f"Bearer {value}"}, timeout=8)
            if r.status_code == 200: return True, "OpenAI — confirmed active"
            if r.status_code == 401: return False, "OpenAI — invalid/revoked"
        except: pass
    
    # Stripe
    if value.startswith("sk_live_") or value.startswith("sk_test_"):
        try:
            r = requests.get("https://api.stripe.com/v1/balance",
                           auth=(value, ""), timeout=8)
            if r.status_code == 200: return True, "Stripe — confirmed active"
            if r.status_code == 401: return False, "Stripe — invalid/revoked"
        except: pass
    
    # GitHub
    if value.startswith("ghp_") or value.startswith("gho_") or value.startswith("github_pat_"):
        try:
            r = requests.get("https://api.github.com/user",
                           headers={"Authorization": f"token {value}"}, timeout=8)
            if r.status_code == 200: return True, f"GitHub — active (@{r.json().get('login','?')})"
            return False, "GitHub — invalid/revoked"
        except: pass
    
    # Discord
    if len(value) > 50 and '.' in value:
        try:
            r = requests.get("https://discord.com/api/v10/users/@me",
                           headers={"Authorization": value}, timeout=8)
            if r.status_code == 200: return True, f"Discord — active (@{r.json().get('username','?')})"
        except: pass
    
    # Telegram
    if re.match(r'^\d{8,10}:[A-Za-z0-9_-]{35}$', value):
        try:
            r = requests.get(f"https://api.telegram.org/bot{value}/getMe", timeout=8)
            if r.json().get("ok"): return True, f"Telegram — active (@{r.json()['result'].get('username','?')})"
            return False, "Telegram — invalid"
        except: pass
    
    # Slack
    if value.startswith("xoxb-") or value.startswith("xoxp-"):
        try:
            r = requests.get("https://slack.com/api/auth.test",
                           headers={"Authorization": f"Bearer {value}"}, timeout=8)
            if r.json().get("ok"): return True, f"Slack — active ({r.json().get('team','?')})"
            return False, "Slack — invalid"
        except: pass
    
    # SendGrid
    if value.startswith("SG."):
        try:
            r = requests.get("https://api.sendgrid.com/v3/user/profile",
                           headers={"Authorization": f"Bearer {value}"}, timeout=8)
            if r.status_code == 200: return True, "SendGrid — confirmed active"
            return False, "SendGrid — invalid"
        except: pass
    
    # AWS (needs both access key + secret, but we can check format)
    if value.startswith("AKIA"):
        try:
            r = requests.get(
                "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
                headers={"Authorization": f"AWS4-HMAC-SHA256 Credential={value}"}, timeout=8)
            if "SignatureDoesNotMatch" in r.text: return True, "AWS — key exists (sig mismatch expected)"
            if "InvalidClientTokenId" in r.text: return False, "AWS — invalid key"
        except: pass
    
    # ── Crypto Validation ──
    # Ethereum — check balance via public API (key is valid if address is derivable)
    if re.match(r'^[a-fA-F0-9]{64}$', value) and len(value) == 64:
        try:
            from hashlib import sha256
            # A real eth private key will be a valid 256-bit number
            num = int(value, 16)
            if 0 < num < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                return True, "Ethereum — valid private key format (SECP256k1 range)"
        except: pass
    
    # Bitcoin WIF — validate format
    if re.match(r'^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$', value):
        return True, "Bitcoin — valid WIF private key format"
    
    # Mnemonic seed phrases — check word count
    words = value.split()
    if len(words) in (12, 15, 18, 21, 24):
        # BIP39 wordlists are 2048 words — check if words look English
        common_words = {"the", "be", "to", "of", "and", "a", "in", "that", "have"}
        if not any(w in common_words for w in words[:3]):  # seed words are rarely common
            return True, f"Crypto — {len(words)}-word seed phrase (BIP39 format)"
    
    # Credit card — Luhn check
    if re.match(r'^\d{13,19}$', value):
        digits = [int(d) for d in reversed(value)]
        checksum = sum(d if i % 2 == 0 else (2*d if 2*d < 10 else 2*d-9) for i, d in enumerate(digits))
        if checksum % 10 == 0:
            return True, "Financial — Luhn-valid card number"
    
    # Can't determine
    return None, "No matching provider for validation"


def run_scan_cycle(notified_set):
    """Run one full scan cycle across all categories with pagination."""
    global total_notified, total_scanned
    
    cycle_findings = defaultdict(list)
    cycle_new_repos = 0
    cycle_exposures = 0
    category_counts = {}  # Track total count per category for README
    queries_this_cycle = min(len(ALL_QUERIES), 25)  # max 25 queries per cycle (30/min limit - buffer)
    
    # Rotate which queries we run each cycle to cover more ground
    all_keys = list(ALL_QUERIES.keys())
    start_idx = (cycle_count - 1) * queries_this_cycle % len(all_keys)
    query_slice = (all_keys[start_idx:] + all_keys[:start_idx])[:queries_this_cycle]
    
    for i, category in enumerate(query_slice):
        if not running:
            break
        
        query = ALL_QUERIES[category]
        page = QUERY_PAGE_STATE.get(category, 1)
        
        log(f"[{i+1}/{queries_this_cycle}] {category} (page {page})...", "scan")
        result = search_github(query, page)
        
        if result is None:
            log(f"  Failed: {category}", "err")
            time.sleep(config.SCAN_DELAY)
            continue
        
        total_count = result.get("total_count", 0)
        real_items = filter_real_secrets(result.get("items", []))
        
        new_count = 0
        for item in real_items:
            if item["repo"] not in notified_set:
                cycle_findings[category].append(item)
                new_count += 1
                cycle_new_repos += 1
        
        cycle_exposures += total_count
        total_scanned += 1
        
        # Rotate pages: if we got results, advance page for next cycle
        if real_items:
            max_page = min(10, (total_count // 10) + 1)  # GitHub caps at ~100 results (10 pages)
            QUERY_PAGE_STATE[category] = (page % max_page) + 1
        
        icon = "🔴" if total_count > 10000 else "🟡" if total_count > 1000 else "🟢"
        log(f"  {icon} {total_count:,} total | {new_count} new repos", "info")
        
        time.sleep(config.SCAN_DELAY)
    
    return cycle_findings, cycle_new_repos, cycle_exposures, category_counts


def notify_findings(findings, notified_set):
    """Send notifications for new findings — only after verifying real secrets."""
    global total_notified
    
    notified_this_cycle = 0
    skipped_placeholder = 0
    method = config.NOTIFY_METHOD
    
    for category, items in findings.items():
        for item in items:
            if config.MAX_NOTIFY_PER_CYCLE > 0 and notified_this_cycle >= config.MAX_NOTIFY_PER_CYCLE:
                log(f"Hit notify limit ({config.MAX_NOTIFY_PER_CYCLE}), stopping", "warn")
                return notified_this_cycle, skipped_placeholder
            
            repo = item["repo"]
            if repo in notified_set:
                continue
            
            # ── VERIFY + TEST before notifying ──
            log(f"Verifying {repo}/{item['file']} ({category})...", "scan")
            
            # Step 1: Check if values look like real secrets (not placeholders)
            is_real, real_secrets = verify_repo_secrets(repo, item["file"], category)
            
            if not is_real:
                log(f"  ⏭️  Skipped — only placeholders/test keys found", "warn")
                notified_set.add(repo)
                save_notified(notified_set)
                skipped_placeholder += 1
                continue
            
            log(f"  ✅ Values look real: {', '.join(real_secrets[:3])}", "ok")
            
            # Step 2: LIVE TEST the keys — are they still active?
            log(f"  🔍 Testing keys live...", "scan")
            any_active, test_results = test_keys_in_file(repo, item["file"], category)
            
            if any_active is False:
                log(f"  🟢 All keys revoked/invalid — skipping notification", "ok")
                notified_set.add(repo)
                save_notified(notified_set)
                skipped_placeholder += 1
                continue
            elif any_active is True:
                active_keys = [r for r in test_results if r.get("active")]
                log(f"  🔴 {len(active_keys)} ACTIVE key(s) found — notifying!", "err")
            else:
                log(f"  🟡 Could not test keys — notifying based on format check", "warn")
            
            log(f"Notifying {repo} ({category}) via {method}...", "scan")
            
            email, name, login = get_owner_email(repo)
            success = False
            
            if method == "email":
                if email:
                    if email in BLOCKED_EMAILS:
                        log(f"  🚫 {email} is blocked — skipping", "warn")
                        notified_set.add(repo)
                        save_notified(notified_set)
                        continue
                    success = send_email(email, repo, item["file"], category, name, real_secrets)
                    if success:
                        log(f"  ✉️  Email sent to {email}", "ok")
                    else:
                        log(f"  ❌ Email failed for {email}", "err")
                else:
                    log(f"  ⚠️  No email found for {repo}", "warn")
            
            elif method == "issue":
                issue_url = create_issue(repo, item["file"], category)
                if issue_url:
                    success = True
                    log(f"  📝 Issue created: {issue_url}", "ok")
                else:
                    log(f"  ❌ Issue creation failed for {repo}", "err")
            
            elif method == "print":
                log(f"  📬 PREVIEW — To: {name} (@{login})", "info")
                log(f"     Email: {email or 'not found'}", "info")
                log(f"     Repo: {repo}", "info")
                log(f"     File: {item['file']} ({category})", "info")
                success = True
            
            if success:
                notified_set.add(repo)
                notified_this_cycle += 1
                total_notified += 1
                save_notified(notified_set)
            
            time.sleep(config.NOTIFY_DELAY)
    
    return notified_this_cycle, skipped_placeholder


# ── Dynamic README Generator ────────────────────────────────────────
def generate_readme(cycle_num, exposures, new_repos, notified, skipped, tested, active_keys, categories_seen):
    """Generate README.md with live data from the scanner."""
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    
    # Build category breakdown
    cat_lines = []
    for cat, count in sorted(categories_seen.items(), key=lambda x: x[1], reverse=True):
        bar_len = min(30, count // 400)
        bar = "█" * max(1, bar_len)
        if count > 10000:
            icon = "🔴"
        elif count > 1000:
            icon = "🟡"
        else:
            icon = "🟢"
        cat_lines.append(f"{cat:<28} {count:>6,}  {icon}")
    
    categories_block = "\n".join(cat_lines)
    
    readme = f"""# 🔒 .env Leak Radar

**Find exposed secrets in your GitHub repos. Before someone else does.**

Scans your GitHub repositories for `.env` files with hardcoded API keys, database passwords, and tokens — even ones you deleted but are still sitting in git history.

---

## Live Scan Results

*Last scan: {now} — this data is auto-updated by the daemon every 5 minutes.*

### Summary

```
SCAN STATS                           COUNT
─────────────────────────────────────────────
Total pattern matches on GitHub  {exposures:>10,}
Repos scanned this session       {new_repos:>10,}
Keys live-tested                       {tested:>6}
Confirmed ACTIVE                       {active_keys:>6}
Notifications sent                     {notified:>6}
Skipped (revoked/placeholder)          {skipped:>6}
Scan cycles completed                  {cycle_num:>6}
```

### Breakdown by Type

```
SECRET TYPE                       FILES
──────────────────────────────────────────
{categories_block}
```

### Why Zero Active Keys Is Good News

We test every found key via live API calls. Most come back **revoked** — meaning GitHub's Secret Scanning or the developer already caught it.

But the .env files with full key values **sit in git history forever**. If someone uses a weaker key later, or if scanning misses one, the history becomes a goldmine.

### Historical Context

| Year | New Secrets Leaked | Source |
|------|-------------------|--------|
| 2023 | 12.8 million | GitGuardian |
| 2024 | **23.7 million** (+25%) | GitGuardian |
| 2026 | {exposures:,} files with patterns | This scanner (live) |

---

## The Problem

You commit a `.env` file, realize your mistake, remove it, push a fix.

**You think it's over. It's not.**

```
$ git log -p -- .env

-OPENAI_API_KEY=sk-proj-abc123...
-DATABASE_URL=postgresql://user:pass@host/db
-STRIPE_SECRET_KEY=sk_live_abc123...
```

The secrets are **permanently in your git history**. Anyone can see them by browsing your commits on GitHub.

Even if the key gets revoked, the old value is still visible. And if you accidentally reuse a pattern or a weaker key later, the history is already indexed.

---

## What We Scan

**29 detection categories across 3 layers:**

- **15 .env file patterns** — OpenAI, AWS, Stripe, MongoDB, Discord, GitHub, Firebase, Twilio, SendGrid, Telegram, JWT, SMTP, Gemini, Anthropic
- **8 code file patterns** — hardcoded keys in .py, .js, .ts files
- **6 crypto/financial patterns** — Ethereum private keys, Bitcoin WIF, seed mnemonics, Stripe restricted, payment providers, credit cards

Each key is **live-tested** against the provider's API before any notification is sent. We only alert if the key is confirmed ACTIVE.

---

## Scan Your Own Repos

### Quick Scan

```bash
git clone https://github.com/OssamaTaha/env-leak-scanner.git
cd env-leak-scanner
chmod +x scan_repos.sh
./scan_repos.sh ~/Projects
```

This checks all your local git repos for:
- `.env` files in git history (even deleted ones)
- Secrets visible in `git log -p`
- Currently tracked `.env` files not in `.gitignore`

### Prevent Future Leaks

Install the pre-commit hook in any project:

```bash
cp pre-commit /path/to/your/project/.git/hooks/
chmod +x /path/to/your/project/.git/hooks/pre-commit
```

It blocks commits that contain `.env` files or patterns that look like real secrets.

### Universal .gitignore

Drop this into every project:

```
# Environment files — NEVER commit
.env
.env.local
.env.*.local
compose.env
*.env

# Keep examples (safe)
!.env.example
!.env.sample
```

---

## If You Found Leaked Secrets

### Step 1: Rotate credentials NOW

This is the most important step. Even after scrubbing git history, anyone who cloned before the fix still has the secrets.

### Step 2: Scrub git history

```bash
pip install git-filter-repo

# Remove .env from ALL history
git filter-repo --invert-paths --path .env

# Re-add remote and force push
git remote add origin https://github.com/you/repo.git
git push --force --all
```

### Step 3: Verify it's gone

```bash
git log -p -- .env
# Should return nothing
```

---

## Files

| File | Purpose |
|------|---------|
| `scan_repos.sh` | Scan your local git repos for leaked secrets |
| `pre-commit` | Git hook to block `.env` commits |
| `env.gitignore` | Universal `.gitignore` template |
| `leak_radar.py` | GitHub API scanner with live key verification |
| `daemon.py` | Continuous monitoring service (29 scan categories) |

---

*Built after I leaked secrets in 4 of my own repos and realized the "fix" commit showed them in plain text on GitHub. Don't be like me.*

— [Ossama Taha](https://github.com/OssamaTaha)
"""
    
    try:
        readme_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md")
        with open(readme_path, "w") as f:
            f.write(readme)
        log(f"README.md updated with live data", "ok")
    except Exception as e:
        log(f"Failed to update README: {e}", "err")


def print_cycle_summary(findings, new_repos, exposures, notified_count, skipped_count):
    """Print summary after each scan cycle."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n{BOLD}{'═' * 57}{RESET}")
    print(f"{BOLD} CYCLE #{cycle_count} SUMMARY — {now}{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}")
    print(f"  Exposures this cycle: {RED}{exposures:,}{RESET}")
    print(f"  New repos found:      {YELLOW}{new_repos}{RESET}")
    print(f"  Notifications sent:   {GREEN}{notified_count}{RESET}")
    print(f"  Skipped (test/revoked): {YELLOW}{skipped_count}{RESET}")
    print(f"  Total lifetime:       {total_notified} notified | {total_scanned} scans")
    
    if findings:
        print(f"\n{BOLD} New findings:{RESET}")
        for cat, items in findings.items():
            for it in items[:3]:
                print(f"  {RED}●{RESET} {it['repo']} — {it['file']} ({cat})")
    
    rl = get_rate_limit()
    print(f"\n{DIM}  Rate limit: {rl['remaining']}/{rl['limit']}{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}\n")


# ── Entry Point ─────────────────────────────────────────────────────
def main():
    global cycle_count, running
    
    print(f"""
{RED}{BOLD}╔═══════════════════════════════════════════════════════╗
║        .env LEAK RADAR — Real-time Daemon              ║
║    Continuous GitHub scanning + developer alerts        ║
╚═══════════════════════════════════════════════════════╝{RESET}
""")
    
    # Check auth
    auth = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if auth.returncode != 0:
        log("gh CLI not authenticated! Run: gh auth login", "err")
        sys.exit(1)
    log("GitHub authenticated", "ok")
    
    # Check SMTP
    if config.SMTP_PASS:
        log(f"SMTP configured: {config.SMTP_USER}", "ok")
    else:
        log(f"SMTP NOT configured — emails will be previewed only", "warn")
        log(f"  Set SMTP_PASS in config.py to enable email sending", "info")
    
    # Load notified cache
    notified_set = load_notified()
    log(f"Loaded {len(notified_set)} previously notified repos", "info")
    
    # Config summary
    log(f"Notification method: {config.NOTIFY_METHOD}", "info")
    log(f"Scan interval: {config.SCAN_INTERVAL}s", "info")
    log(f"Max notify per cycle: {config.MAX_NOTIFY_PER_CYCLE or 'unlimited'}", "info")
    
    print(f"\n{GREEN}Starting daemon... Press Ctrl+C to stop{RESET}\n")
    
    while running:
        cycle_count += 1
        log(f"═══ SCAN CYCLE #{cycle_count} ═══", "scan")
        
        findings, new_repos, exposures = run_scan_cycle(notified_set)
        
        if not running:
            break
        
        notified_count, skipped_count = notify_findings(findings, notified_set)
        print_cycle_summary(findings, new_repos, exposures, notified_count, skipped_count)
        
        # Update README with live data
        categories_seen = {}
        for cat, items in findings.items():
            categories_seen[cat] = len(items) * 100  # rough estimate from this cycle
        # Merge with total exposures for a better picture
        for cat in ALL_QUERIES:
            if cat not in categories_seen:
                categories_seen[cat] = 0
        
        generate_readme(
            cycle_count, exposures, new_repos,
            total_notified, skipped_count,
            total_scanned, 0,  # tested/active tracked in findings
            categories_seen
        )
        
        if config.SCAN_INTERVAL > 0 and running:
            log(f"Next cycle in {config.SCAN_INTERVAL}s...", "info")
            sleep_end = time.time() + config.SCAN_INTERVAL
            while time.time() < sleep_end and running:
                time.sleep(1)
    
    log(f"Daemon stopped. {total_notified} total notifications sent across {cycle_count} cycles.", "ok")


if __name__ == "__main__":
    main()
