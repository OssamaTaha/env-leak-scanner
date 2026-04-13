"""
.env Leak Radar — Configuration Template
Copy this to config.py and fill in your values.
config.py is in .gitignore and will NEVER be committed.
"""

# ── SMTP Configuration (Gmail App Password) ─────────────────────────
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your-email@gmail.com"
SMTP_PASS = "your-gmail-app-password-here"  # NOT your login password!
FROM_EMAIL = "your-email@gmail.com"
FROM_NAME = "env-leak-scanner"

# ── Scanner Settings ────────────────────────────────────────────────
SCAN_DELAY = 4           # Seconds between search queries
NOTIFY_DELAY = 10        # Seconds between notifications
MAX_RESULTS_PER_QUERY = 15
SCAN_INTERVAL = 300      # Seconds between full scan cycles (0 = one-shot)
NOTIFY_METHOD = "email"  # "email", "issue", or "print"
MAX_NOTIFY_PER_CYCLE = 5
NOTIFIED_CACHE = "notified_repos.json"
