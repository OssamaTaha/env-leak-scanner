#!/usr/bin/env python3
"""
.env Leak Radar — Real-time GitHub secret exposure scanner
Uses gh CLI (authenticated) with proper rate limit handling.
Can notify repo owners about exposed secrets.
"""

import subprocess
import json
import sys
import time
import argparse
from datetime import datetime, timezone
from collections import defaultdict
from notify import notify_owner, batch_notify, get_contact_info

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


def get_rate_limit():
    """Get current rate limit status via gh CLI."""
    try:
        r = subprocess.run(
            ["gh", "api", "/rate_limit"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            data = json.loads(r.stdout)
            search = data.get("resources", {}).get("search", {})
            return {
                "remaining": search.get("remaining", 0),
                "limit": search.get("limit", 0),
                "reset": search.get("reset", 0),
            }
    except Exception:
        pass
    return {"remaining": 0, "limit": 0, "reset": 0}


def wait_for_reset(reset_time):
    """Wait until rate limit resets with countdown."""
    now = int(time.time())
    wait = max(0, reset_time - now) + 2
    
    if wait <= 0:
        return
    
    reset_local = datetime.fromtimestamp(reset_time, tz=timezone.utc).astimezone()
    print(f"\n{YELLOW}⏳ Rate limited. Resets at {reset_local.strftime('%H:%M:%S %Z')}{RESET}")
    
    while wait > 0:
        mins, secs = divmod(wait, 60)
        print(f"\r{YELLOW}   ⏳ {mins:02d}:{secs:02d} remaining{RESET}   ", end="", flush=True)
        time.sleep(1)
        wait -= 1
    
    print(f"\r{GREEN}   ✅ Rate limit reset. Continuing...{RESET}          ")


def search_github(query):
    """Search GitHub code via gh CLI with rate limit handling."""
    rl = get_rate_limit()
    if rl["remaining"] < 2:
        wait_for_reset(rl["reset"])
    
    try:
        r = subprocess.run(
            ["gh", "api", "search/code", "-X", "GET",
             "-f", f"q={query}", "-f", "per_page=15"],
            capture_output=True, text=True, timeout=30
        )
        
        if r.returncode != 0:
            if "rate limit" in r.stderr.lower() or "403" in r.stderr:
                wait_for_reset(int(time.time()) + 60)
                return search_github(query)
            return None
        
        return json.loads(r.stdout)
    except Exception as e:
        print(f"{RED}   ✗ {e}{RESET}")
        return None


def filter_real_secrets(items):
    """Filter to likely real secrets, not examples."""
    skip_keywords = {"example", "sample", "template", "dist", "skeleton",
                     "dummy", "placeholder", "test", "fake", "mock", ".bak"}
    
    real = []
    for item in items:
        path = item.get("path", "")
        repo = item.get("repository", {})
        
        if repo.get("private", True):
            continue
        if any(kw in path.lower() for kw in skip_keywords):
            continue
        
        real.append({
            "repo": repo.get("full_name", ""),
            "file": path,
            "url": item.get("html_url", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
        })
    
    return real


def fmt(n):
    return f"{n:,}"


def print_banner():
    print(f"""
{RED}{BOLD}╔═══════════════════════════════════════════════════════╗
║           .env LEAK RADAR — Live GitHub Scanner        ║
║      Real-time secret exposure detection & stats       ║
╚═══════════════════════════════════════════════════════╝{RESET}
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description=".env Leak Radar — GitHub secret exposure scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 leak_radar.py                          # Scan only
  python3 leak_radar.py --notify print           # Scan + preview notifications
  python3 leak_radar.py --notify email           # Scan + send email notifications
  python3 leak_radar.py --notify issue           # Scan + create GitHub issues
  python3 leak_radar.py --notify print --limit 3 # Scan + notify top 3 only
        """
    )
    parser.add_argument("--notify", choices=["print", "email", "issue"],
                       help="Notification method after scan")
    parser.add_argument("--limit", type=int, default=0,
                       help="Max repos to notify (0 = all)")
    parser.add_argument("--delay", type=int, default=5,
                       help="Seconds between notifications (default: 5)")
    parser.add_argument("--smtp-host", help="SMTP server host")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port")
    parser.add_argument("--smtp-user", help="SMTP username")
    parser.add_argument("--smtp-pass", help="SMTP password")
    parser.add_argument("--from-email", help="Sender email address")
    parser.add_argument("--scan-only", action="store_true",
                       help="Only scan, don't show results table")
    
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()
    
    # Check gh auth
    auth_check = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if auth_check.returncode != 0:
        print(f"{RED}✗ gh CLI not authenticated. Run: gh auth login{RESET}")
        sys.exit(1)
    
    print(f"{GREEN}✓ Authenticated with GitHub{RESET}")
    
    rl = get_rate_limit()
    print(f"{DIM}  Search API calls: {rl['remaining']}/{rl['limit']}{RESET}")
    
    if args.notify:
        print(f"{YELLOW}  📬 Notification mode: {args.notify}{RESET}")
    
    print(f"\n{CYAN}Scanning {len(QUERIES)} secret types...{RESET}\n")
    
    all_findings = defaultdict(list)
    total_exposed = 0
    seen_repos = set()
    
    for i, (category, query) in enumerate(QUERIES.items(), 1):
        label = f"[{i:2d}/{len(QUERIES)}] {category:<20}"
        print(f"{DIM}{label}{RESET} ", end="", flush=True)
        
        result = search_github(query)
        
        if result is None:
            print(f"{RED}✗ failed{RESET}")
            time.sleep(7)
            continue
        
        total_count = result.get("total_count", 0)
        real_items = filter_real_secrets(result.get("items", []))
        
        new_repos = sum(1 for it in real_items if it["repo"] not in seen_repos)
        for it in real_items:
            if it["repo"] not in seen_repos:
                seen_repos.add(it["repo"])
                all_findings[category].append(it)
        
        total_exposed += total_count
        
        if total_count > 10000:
            color, icon = RED, "🔴"
        elif total_count > 1000:
            color, icon = YELLOW, "🟡"
        else:
            color, icon = GREEN, "🟢"
        
        print(f"{icon} {color}{fmt(total_count):>8}{RESET} total | "
              f"{GREEN}{new_repos}{RESET} unique repos")
        
        if i < len(QUERIES):
            rl = get_rate_limit()
            if rl["remaining"] < 3:
                wait_for_reset(rl["reset"])
            else:
                time.sleep(3)
    
    # ── Results Summary ─────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 57}{RESET}")
    print(f"{BOLD} SCAN RESULTS — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}")
    print(f"  Total exposures found: {RED}{fmt(total_exposed)}{RESET}")
    print(f"  Unique repos found:    {fmt(len(seen_repos))}")
    
    # ── By Category ────────────────────────────────────────────
    print(f"\n{BOLD} EXPOSURES BY TYPE{RESET}")
    print(f"{BOLD}{'─' * 57}{RESET}")
    
    sorted_cats = sorted(
        [(cat, len(items)) for cat, items in all_findings.items()],
        key=lambda x: x[1], reverse=True
    )
    
    for cat, count in sorted_cats:
        bar = "█" * min(30, count * 2)
        color = RED if count > 10 else YELLOW if count > 5 else GREEN
        print(f"  {cat:<20} {color}{count:>4}{RESET} repos  {color}{bar}{RESET}")
    
    # ── Top Repos ──────────────────────────────────────────────
    print(f"\n{BOLD} TOP EXPOSED REPOS{RESET}")
    print(f"{BOLD}{'─' * 57}{RESET}")
    
    all_repos = []
    for cat, items in all_findings.items():
        for it in items:
            it["category"] = cat
            all_repos.append(it)
    
    all_repos.sort(key=lambda x: x.get("stars", 0), reverse=True)
    
    for it in all_repos[:15]:
        stars = f" ⭐{it['stars']}" if it.get("stars", 0) > 0 else ""
        lang = f" [{it['language']}]" if it.get("language") else ""
        print(f"  {RED}●{RESET} {it['repo']}{stars}{lang}")
        print(f"    {DIM}{it['file']}{RESET}")
        print(f"    {DIM}{it['url']}{RESET}")
    
    # ── Save Report ────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"leak_report_{ts}.json"
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_exposures": total_exposed,
        "unique_repos": len(seen_repos),
        "categories": {cat: len(items) for cat, items in all_findings.items()},
        "findings": dict(all_findings),
    }
    
    with open(outfile, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{GREEN}✓ Report saved: {outfile}{RESET}")
    
    # ── Notifications ──────────────────────────────────────────
    if args.notify:
        smtp_config = None
        if args.notify == "email":
            if not all([args.smtp_host, args.smtp_user, args.smtp_pass, args.from_email]):
                print(f"\n{RED}✗ Email mode requires: --smtp-host, --smtp-user, --smtp-pass, --from-email{RESET}")
                print(f"{DIM}  Falling back to print mode.{RESET}")
                args.notify = "print"
            else:
                smtp_config = {
                    "host": args.smtp_host,
                    "port": args.smtp_port,
                    "username": args.smtp_user,
                    "password": args.smtp_pass,
                    "from_email": args.from_email,
                }
        
        # Limit notifications if requested
        findings_to_notify = {}
        count = 0
        for cat, items in all_findings.items():
            limited = []
            for item in items:
                if args.limit > 0 and count >= args.limit:
                    break
                limited.append(item)
                count += 1
            if limited:
                findings_to_notify[cat] = limited
        
        batch_notify(findings_to_notify, method=args.notify, 
                    smtp_config=smtp_config, delay=args.delay)
    
    print()


if __name__ == "__main__":
    main()
