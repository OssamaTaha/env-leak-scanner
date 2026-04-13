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
    
    subject = f"🔒 Security heads-up: secrets exposed in {repo_full_name}"
    
    body = f"""Hey {owner_name},

I found that your repository {repo_full_name} has exposed secrets ({secret_type}) in {exposed_file}.

⚠️ WHAT'S EXPOSED:
  File: {exposed_file}
  Type: {secret_type}
  URL: https://github.com/{repo_full_name}/blob/main/{exposed_file}

🔴 WHY IT MATTERS:
  Even if removed in a recent commit, secrets stay in git history FOREVER.
  Anyone can run: git log -p -- {exposed_file}

✅ HOW TO FIX:
  1. ROTATE the exposed credentials NOW
  2. git filter-repo --invert-paths --path {exposed_file}
  3. git push --force --all
  4. Add to .gitignore: .env .env.local .env.*.local

📚 https://github.com/OssamaTaha/env-leak-scanner

This is a friendly automated alert. No judgment — it happens to everyone.

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
    """Send notifications for new findings."""
    global total_notified
    
    notified_this_cycle = 0
    method = config.NOTIFY_METHOD
    
    for category, items in findings.items():
        for item in items:
            if config.MAX_NOTIFY_PER_CYCLE > 0 and notified_this_cycle >= config.MAX_NOTIFY_PER_CYCLE:
                log(f"Hit notify limit ({config.MAX_NOTIFY_PER_CYCLE}), stopping", "warn")
                return notified_this_cycle
            
            repo = item["repo"]
            if repo in notified_set:
                continue
            
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
    
    return notified_this_cycle


def print_cycle_summary(findings, new_repos, exposures, notified_count):
    """Print summary after each scan cycle."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"\n{BOLD}{'═' * 57}{RESET}")
    print(f"{BOLD} CYCLE #{cycle_count} SUMMARY — {now}{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}")
    print(f"  Exposures this cycle: {RED}{exposures:,}{RESET}")
    print(f"  New repos found:      {YELLOW}{new_repos}{RESET}")
    print(f"  Notifications sent:   {GREEN}{notified_count}{RESET}")
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
        
        notified_count = notify_findings(findings, notified_set)
        print_cycle_summary(findings, new_repos, exposures, notified_count)
        
        if config.SCAN_INTERVAL > 0 and running:
            log(f"Next cycle in {config.SCAN_INTERVAL}s...", "info")
            sleep_end = time.time() + config.SCAN_INTERVAL
            while time.time() < sleep_end and running:
                time.sleep(1)
    
    log(f"Daemon stopped. {total_notified} total notifications sent across {cycle_count} cycles.", "ok")


if __name__ == "__main__":
    main()
