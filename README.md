# 🔒 .env Leak Radar

**Find exposed secrets in your GitHub repos. Before someone else does.**

Scans your GitHub repositories for `.env` files with hardcoded API keys, database passwords, and tokens — even ones you deleted but are still sitting in git history.

---

## Live Scan Results

*Scanned April 13, 2026 — verified via live API calls, not just file patterns.*

### The Real Picture

```
                         PATTERN MATCH    LIVE VERIFIED
                         ─────────────    ─────────────
Files with .env patterns      12,292             —
Keys tested live                    —            48
Confirmed ACTIVE                    —             0  ✅
Revoked/invalid                     —            48  🟢
```

**What this means:** GitHub's secret scanning works. Most exposed keys get caught and revoked quickly. But the .env files remain in git history forever — a ticking time bomb if someone rotates to a weaker key or if the scanning misses one.

### Breakdown by Type (pattern matches on GitHub right now)

```
SECRET TYPE              FILES    VERIFIED
─────────────────────────────────────────────────
Anthropic/Claude         2,096    9 tested → all revoked 🟢
Stripe Live Keys         2,984    4 tested → all revoked 🟢
OpenAI API Keys          1,704    6 tested → all revoked 🟢
Database URLs           12,816    — (can't test remotely)
MongoDB URIs             5,344    — (can't test remotely)
JWT Secrets             13,228    — (no endpoint to test)
Discord Tokens           1,040   11 tested → all revoked 🟢
GitHub Tokens            1,108   10 tested → all revoked 🟢
Telegram Bots            1,188   14 tested → all revoked 🟢
Google AI/Gemini         1,168   13 tested → all revoked 🟢
SendGrid Keys            1,004   10 tested → all revoked 🟢
─────────────────────────────────────────────────
Total pattern matches   42,684   48 tested → 0 active
```

### Why Zero Active Keys Is Actually Good News

We expected to find live keys. We found **none**. That means:

1. **GitHub's Secret Scanning works** — it catches patterns and alerts owners
2. **Developers respond** — most rotate keys within hours/days
3. **The system works... mostly**

**But the files are still there.** Even though the keys are revoked, the .env files with full key values sit in git history. If someone uses a weaker key next time, or if GitHub's scanner misses it, the history becomes a goldmine.

### Historical Context

| Year | New Secrets Leaked | Source |
|------|-------------------|--------|
| 2023 | 12.8 million | GitGuardian |
| 2024 | **23.7 million** (+25%) | GitGuardian |
| 2026 | 42,684 files with patterns | GitHub Code Search (this scan) |

The pattern-match numbers are huge. The live-key numbers are near zero. **The gap is the success of automated secret scanning** — but it doesn't clean up the history.

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
| `daemon.py` | Continuous monitoring service |

---

*Built after I leaked secrets in 4 of my own repos and realized the "fix" commit showed them in plain text on GitHub. Don't be like me.*

— [Ossama Taha](https://github.com/OssamaTaha)
