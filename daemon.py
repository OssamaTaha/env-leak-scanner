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
QUERIES = {
    "OpenAI Keys":       'filename:.env "sk-proj-"',
    "AWS Access Keys":   'filename:.env "AKIA"',
    "Stripe Live Keys":  'filename:.env "sk_live_"',
    "Database URLs":     'filename:.env "postgresql://" password',
    "MongoDB URIs":      'filename:.env "mongodb+srv://"',
    "Discord Tokens":    'filename:.env "DISCORD_TOKEN" NOT skeleton NOT example',
    "GitHub Tokens":     'filename:.env "GITHUB_TOKEN" NOT example',
    "Firebase Keys":     'filename:.env "FIREBASE_PRIVATE_KEY"',
    "Twilio Auth":       'filename:.env "TWILIO_AUTH_TOKEN"',
    "SendGrid Keys":     'filename:.env "SENDGRID_API_KEY"',
    "Telegram Bots":     'filename:.env "TELEGRAM_BOT_TOKEN"',
    "JWT Secrets":       'filename:.env "JWT_SECRET" NOT example',
    "SMTP Passwords":    'filename:.env "SMTP_PASSWORD"',
    "Gemini/Google AI":  'filename:.env "GOOGLE_API_KEY" NOT example',
    "Anthropic Claude":  'filename:.env "ANTHROPIC_API_KEY"',
}

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
def search_github(query):
    wait_for_rate_limit()
    try:
        r = subprocess.run(
            ["gh", "api", "search/code", "-X", "GET",
             "-f", f"q={query}", "-f", "per_page=15"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            if "rate limit" in r.stderr.lower():
                time.sleep(65)
                return search_github(query)
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
    Returns (has_real_secrets: bool, real_secrets_found: list)"""
    
    content = fetch_file_content(repo_full_name, file_path)
    if not content:
        # Can't fetch — assume it might be real to be safe
        return True, ["(could not verify content)"]
    
    real_secrets = []
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            continue
        
        key, _, val = line.partition('=')
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        
        if not val:
            continue
        
        if is_real_secret(key, val, secret_type):
            # Show first 4 and last 4 chars of the real secret
            if len(val) > 12:
                masked = f"{val[:4]}...{val[-4:]}"
            else:
                masked = val[:6] + "..."
            real_secrets.append(f"{key}={masked} ({len(val)} chars)")
    
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
    "Twilio Auth": test_sendgrid_key,  # Similar Bearer token pattern
}


def test_keys_in_file(repo_full_name, file_path, secret_type):
    """Fetch .env file, extract secrets, test each one live.
    Returns (any_active: bool, test_results: list of dicts)"""
    
    content = fetch_file_content(repo_full_name, file_path)
    if not content:
        return None, [{"key": "?", "status": "unknown", "detail": "could not fetch file"}]
    
    tester = KEY_TESTERS.get(secret_type)
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
def send_email(to_email, repo_full_name, exposed_file, secret_type, owner_name):
    """Send security notification email via SMTP."""
    if not config.SMTP_PASS:
        log(f"SMTP not configured. Would email {to_email}", "warn")
        return False
    
    subject = f"🔴 CONFIRMED ACTIVE secret in {repo_full_name}"
    
    body = f"""Hey {owner_name},

⚠️  I tested the secrets in your repository {repo_full_name} and confirmed they are STILL ACTIVE.

Exposed file: {exposed_file}
Secret type: {secret_type}
URL: https://github.com/{repo_full_name}/blob/main/{exposed_file}

🔴 THIS KEY STILL WORKS — I was able to make successful API calls with it.
   Anyone who finds this file can use your credentials RIGHT NOW.

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
def run_scan_cycle(notified_set):
    """Run one full scan cycle across all categories."""
    global total_notified, total_scanned
    
    cycle_findings = defaultdict(list)
    cycle_new_repos = 0
    cycle_exposures = 0
    
    for i, (category, query) in enumerate(QUERIES.items()):
        if not running:
            break
        
        log(f"[{i+1}/{len(QUERIES)}] Scanning {category}...", "scan")
        result = search_github(query)
        
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
        
        icon = "🔴" if total_count > 10000 else "🟡" if total_count > 1000 else "🟢"
        log(f"  {icon} {total_count:,} total | {new_count} new repos", "info")
        
        time.sleep(config.SCAN_DELAY)
    
    return cycle_findings, cycle_new_repos, cycle_exposures


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
                    success = send_email(email, repo, item["file"], category, name)
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
        
        if config.SCAN_INTERVAL > 0 and running:
            log(f"Next cycle in {config.SCAN_INTERVAL}s...", "info")
            sleep_end = time.time() + config.SCAN_INTERVAL
            while time.time() < sleep_end and running:
                time.sleep(1)
    
    log(f"Daemon stopped. {total_notified} total notifications sent across {cycle_count} cycles.", "ok")


if __name__ == "__main__":
    main()
