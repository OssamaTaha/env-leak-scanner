#!/usr/bin/env python3
"""
.env Leak Radar — Notification Module
Send friendly alerts to repo owners about exposed secrets.
"""

import subprocess
import json
import re
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from urllib.parse import urlparse

# ── Colors ──────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def get_repo_owner_info(repo_full_name):
    """Get owner info from GitHub API."""
    owner = repo_full_name.split("/")[0]
    
    try:
        r = subprocess.run(
            ["gh", "api", f"users/{owner}"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return json.loads(r.stdout)
    except Exception:
        pass
    return None


def get_commit_emails(repo_full_name, limit=5):
    """Extract unique emails from recent commits."""
    emails = set()
    
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo_full_name}/commits?per_page={limit}",
             "-q", ".[].commit.author.email"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            for email in r.stdout.strip().split("\n"):
                email = email.strip()
                if email and "noreply" not in email:
                    emails.add(email)
    except Exception:
        pass
    
    return list(emails)


def get_contact_info(repo_full_name):
    """Gather all available contact methods for a repo owner."""
    info = {
        "repo": repo_full_name,
        "login": "",
        "name": "",
        "email": None,
        "commit_emails": [],
        "blog": None,
        "twitter": None,
        "profile_url": f"https://github.com/{repo_full_name.split('/')[0]}",
    }
    
    # Get user profile
    user_data = get_repo_owner_info(repo_full_name)
    if user_data:
        info["login"] = user_data.get("login", "")
        info["name"] = user_data.get("name", "") or info["login"]
        info["email"] = user_data.get("email")  # Public email if set
        info["blog"] = user_data.get("blog", "") or None
        info["twitter"] = user_data.get("twitter_username")
    
    # Get commit emails as fallback
    info["commit_emails"] = get_commit_emails(repo_full_name)
    
    return info


def generate_message(repo_full_name, exposed_file, secret_type, contact_name=None):
    """Generate a friendly notification message."""
    name = contact_name or "there"
    file_url = f"https://github.com/{repo_full_name}/blob/main/{exposed_file}"
    
    # Check if file still exists in default branch
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo_full_name}/contents/{exposed_file}",
             "-q", ".html_url"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            file_url = r.stdout.strip()
    except Exception:
        pass
    
    subject = f"🔒 Security heads-up: Potential secret exposure in {repo_full_name}"
    
    body = f"""Hey {name},

I came across your repository {repo_full_name} and noticed that {exposed_file} may contain exposed secrets ({secret_type}).

⚠️  WHAT'S EXPOSED:
    File: {exposed_file}
    Type: {secret_type}
    URL: {file_url}

🔴  WHY IT MATTERS:
    Even if you've removed the file in a recent commit, the secrets remain in your git history FOREVER. Anyone can run:

        git log -p -- {exposed_file}

    ...and see all the deleted content including your API keys, passwords, and tokens.

✅  HOW TO FIX:
    1. ROTATE the exposed credentials immediately (this is the most important step!)
    2. Scrub git history with: git filter-repo --invert-paths --path {exposed_file}
    3. Force push: git push --force --all
    4. Add to .gitignore: .env, .env.local, .env.*.local

📚  RESOURCES:
    - Scanner tool: https://github.com/OssamaTaha/env-leak-scanner
    - git-filter-repo: https://github.com/newren/git-filter-repo
    - GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning

This is an automated but friendly notification. I built a scanner that finds exposed .env files on GitHub, and yours came up. No judgment — it happens to the best of us (including me 😅).

Stay secure! 🛡️

— Sent by env-leak-scanner
   https://github.com/OssamaTaha/env-leak-scanner
"""
    
    return subject, body


def send_email_notification(to_email, subject, body, smtp_config=None):
    """Send email notification via SMTP."""
    if not smtp_config:
        print(f"{YELLOW}  ⚠ No SMTP config. Printing message instead.{RESET}")
        return False
    
    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_config["from_email"]
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        
        with smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587)) as server:
            server.starttls()
            server.login(smtp_config["username"], smtp_config["password"])
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"{RED}  ✗ Email failed: {e}{RESET}")
        return False


def create_github_issue(repo_full_name, title, body):
    """Create a GitHub issue as notification (if repo allows)."""
    try:
        r = subprocess.run(
            ["gh", "issue", "create",
             "--repo", repo_full_name,
             "--title", title,
             "--body", body],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            return r.stdout.strip()
        else:
            return f"Error: {r.stderr.strip()[:200]}"
    except Exception as e:
        return f"Error: {e}"


def notify_owner(repo_full_name, exposed_file, secret_type, method="print", smtp_config=None):
    """Main notification function — supports email, issue, or print."""
    print(f"\n{CYAN}  📬 Gathering contact info for {repo_full_name}...{RESET}")
    
    contact = get_contact_info(repo_full_name)
    subject, body = generate_message(
        repo_full_name, exposed_file, secret_type,
        contact_name=contact.get("name")
    )
    
    print(f"  {DIM}Owner: {contact['name']} (@{contact['login']}){RESET}")
    print(f"  {DIM}Profile: {contact['profile_url']}{RESET}")
    
    if contact["email"]:
        print(f"  {DIM}Email: {contact['email']}{RESET}")
    if contact["commit_emails"]:
        print(f"  {DIM}Commit emails: {', '.join(contact['commit_emails'])}{RESET}")
    if contact["blog"]:
        print(f"  {DIM}Blog: {contact['blog']}{RESET}")
    if contact["twitter"]:
        print(f"  {DIM}Twitter: @{contact['twitter']}{RESET}")
    
    result = {"method": method, "success": False, "contact": contact}
    
    if method == "email":
        # Try profile email first, then commit emails
        target_email = contact["email"] or (contact["commit_emails"][0] if contact["commit_emails"] else None)
        
        if target_email:
            print(f"  {YELLOW}  → Sending email to {target_email}...{RESET}")
            result["success"] = send_email_notification(target_email, subject, body, smtp_config)
            result["target"] = target_email
        else:
            print(f"  {YELLOW}  ⚠ No email found for {repo_full_name}{RESET}")
    
    elif method == "issue":
        print(f"  {YELLOW}  → Creating GitHub issue...{RESET}")
        issue_url = create_github_issue(repo_full_name, subject, body)
        result["success"] = "github.com" in issue_url
        result["issue_url"] = issue_url
        if result["success"]:
            print(f"  {GREEN}  ✓ Issue created: {issue_url}{RESET}")
    
    elif method == "print":
        print(f"\n{BOLD}{'─' * 57}{RESET}")
        print(f"{BOLD} NOTIFICATION PREVIEW{RESET}")
        print(f"{BOLD}{'─' * 57}{RESET}")
        print(f"  To: {contact['name']} (@{contact['login']})")
        print(f"  Via: Profile ({contact['profile_url']})")
        if contact["email"]:
            print(f"  Email: {contact['email']}")
        print(f"\n{BOLD}  Subject:{RESET} {subject}")
        print(f"\n{DIM}{body}{RESET}")
        print(f"{BOLD}{'─' * 57}{RESET}")
        result["success"] = True
    
    return result


def batch_notify(findings, method="print", smtp_config=None, delay=5):
    """Notify multiple repo owners about their exposed secrets."""
    print(f"\n{BOLD}📬 NOTIFICATION MODE: {method.upper()}{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}\n")
    
    notified = []
    skipped = []
    
    for category, items in findings.items():
        for item in items:
            repo = item["repo"]
            file = item["file"]
            
            print(f"{CYAN}● {repo}{RESET}")
            print(f"  File: {file}")
            print(f"  Type: {category}")
            
            result = notify_owner(repo, file, category, method=method, smtp_config=smtp_config)
            
            if result["success"]:
                notified.append(result)
            else:
                skipped.append(result)
            
            # Delay between notifications to be respectful
            if delay > 0:
                time.sleep(delay)
    
    # Summary
    print(f"\n{BOLD}{'═' * 57}{RESET}")
    print(f"{BOLD} NOTIFICATION SUMMARY{RESET}")
    print(f"{BOLD}{'═' * 57}{RESET}")
    print(f"  Sent:    {GREEN}{len(notified)}{RESET}")
    print(f"  Skipped: {YELLOW}{len(skipped)}{RESET}")
    
    return notified, skipped


if __name__ == "__main__":
    # Demo: notify one repo
    import sys
    if len(sys.argv) > 1:
        repo = sys.argv[1]
        file = sys.argv[2] if len(sys.argv) > 2 else ".env"
        secret_type = sys.argv[3] if len(sys.argv) > 3 else "Unknown"
        notify_owner(repo, file, secret_type, method="print")
    else:
        print("Usage: python notify.py <owner/repo> [file] [secret_type]")
