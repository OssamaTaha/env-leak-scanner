# 🚨 .env Leak Radar

**Real-time GitHub scanner that finds exposed secrets and notifies developers.**

```
Scanning 15 secret types...

[ 1/15] OpenAI Keys          🟡    1,704 total | 3 unique repos
[ 2/15] AWS Access Keys      🟡    2,544 total | 4 unique repos
[ 3/15] Stripe Live Keys     🟡    2,984 total | 3 unique repos
[ 4/15] Database URLs        🔴   12,816 total | 10 unique repos
[ 5/15] MongoDB URIs         🟡    5,344 total | 6 unique repos
...

═════════════════════════════════════════════════════════
 SCAN RESULTS — 2026-04-13 13:41:42
═════════════════════════════════════════════════════════
  Total exposures found: 47,620
  Unique repos found:    98
```

---

## The 2024 Baseline (GitGuardian Report)

In 2024, GitGuardian scanned **1.1 billion commits** and found:

| Metric | 2024 Number |
|--------|-------------|
| New secrets leaked on public GitHub | **23.7 million** (+25% YoY) |
| Unique secrets exposed | **3.7 million** |
| Commits containing secrets | **8 million** |
| Repositories that leaked | **3 million** |
| Developers who leaked a secret | **1 in 10** |
| Secrets still valid after 5 days | **90%** |
| Revoked within 1 hour of alert | **2.6%** |

OpenAI key leaks alone saw a **1,212% increase** due to the GenAI explosion.

That was 2024. It's worse now.

---

## 2026: The Age of Coding Agents

We're in a different world now. Here's what changed:

### 🤖 AI Coding Agents Generate Secrets

Claude Code, Cursor, GitHub Copilot, Replit Agent, Bolt, v0 — they all do the same thing:

1. You say "build me an app with Stripe payments"
2. Agent creates the project structure
3. Agent generates `.env` with placeholder keys
4. Agent commits everything
5. **Agent never mentions `.gitignore`**

The agent doesn't understand that `.env` files contain secrets. It just generates configs because that's what the training data shows. Thousands of developers are pushing AI-generated `.env` files every day without realizing it.

### 🎨 "Vibe Coders" Don't Know About Git

The biggest new category of leaked secrets comes from non-developers building with AI. They:
- Use Cursor/v0 to generate a full app
- Click "commit and push" in the UI
- Have never heard of `.gitignore`
- Don't understand git history
- Ship their Stripe keys and database passwords to public repos

These aren't bad developers. They're designers, founders, students, and hobbyists who just built their first app with AI help. They have no reason to know about secret management — until their AWS bill shows $50,000 in charges.

### 📊 The Real Numbers (April 2026 — Live)

This scanner queries GitHub's Code Search API in real-time. These are **actual counts right now**, not annual estimates:

| Secret Type | Live Count (Apr 2026) |
|-------------|----------------------|
| JWT Secrets | **13,228** |
| Database URLs (PostgreSQL) | **12,816** |
| MongoDB URIs | **5,344** |
| Stripe Keys | **2,984** |
| AWS Access Keys | **2,544** |
| Anthropic/Claude Keys | **2,096** |
| OpenAI Keys | **1,704** |
| Google AI/Gemini Keys | **1,168** |
| Discord Tokens | **1,040** |

And this is just from **one search query per type**. GitHub limits code search to 1,000 results per query. The real number is orders of magnitude higher.

### 🧮 Back-of-Envelope Math

- GitGuardian found **23.7M secrets in 2024** across all types
- Coding agent adoption went from ~5% to ~60% of developers in 2025-2026
- Non-developer "vibe coders" added millions of new public repos
- AI generates `.env` files in ~80% of new projects
- Estimated 2026 secret exposure: **50-80 million new secrets per year**

The problem didn't get better. It got **exponentially worse** because AI made it easy for anyone to create and publish code — but impossible for AI to teach git hygiene in the same flow.

---

## What This Tool Does

### 1. Real-Time GitHub Scan

Scans 15 categories of secrets across GitHub's entire public codebase:

```bash
python3 leak_radar.py
```

Uses GitHub's Code Search API with proper rate limit handling. Respects the 30 req/min limit, waits automatically, shows countdown.

### 2. Notify Developers

After scanning, you can notify affected developers:

```bash
# Preview notification messages
python3 leak_radar.py --notify print

# Send email notifications (requires SMTP config)
python3 leak_radar.py --notify email \
  --smtp-host smtp.gmail.com \
  --smtp-user you@gmail.com \
  --smtp-pass "app-password" \
  --from-email you@gmail.com

# Create GitHub issues on affected repos
python3 leak_radar.py --notify issue

# Limit to top 3 most critical
python3 leak_radar.py --notify print --limit 3
```

The notification:
- Pulls owner email from their GitHub profile and recent commits
- Generates a friendly, non-judgmental security warning
- Explains WHY it's dangerous (git history)
- Shows exact fix steps (git filter-repo + credential rotation)
- Links to this scanner tool

### 3. Local Repo Scanner

Scan your own projects for secrets in git history:

```bash
chmod +x scan_repos.sh
./scan_repos.sh /path/to/your/projects
```

Checks:
- `.env` files in git history (even if removed)
- Currently tracked `.env` files not in `.gitignore`
- Actual secret content visible in `git log -p`

---

## Quick Start

```bash
# Clone
git clone https://github.com/OssamaTaha/env-leak-scanner.git
cd env-leak-scanner

# Scan GitHub (requires gh CLI authenticated)
python3 leak_radar.py

# Scan your local repos
./scan_repos.sh ~/Projects

# Install pre-commit hook in any project
cp pre-commit /path/to/project/.git/hooks/
chmod +x /path/to/project/.git/hooks/pre-commit
```

---

## Why "git rm .env" Doesn't Fix It

```bash
# You do this:
git rm .env
git commit -m "remove .env"
git push

# But anyone can still do this:
git log -p -- .env

# Output shows:
-DATABASE_PASSWORD=supersecret123
-OPENAI_API_KEY=sk-proj-abc123...
-STRIPE_SECRET_KEY=sk_live_abc123...
```

The `-` in the diff shows the deleted line — including your secrets. On GitHub, this is visible in the "Files changed" tab of any commit that touched the file. **FOREVER.**

### The ACTUAL Fix

```bash
# 1. Install git-filter-repo
pip install git-filter-repo

# 2. Erase from ALL history
git filter-repo --invert-paths --path .env

# 3. Re-add remote (filter-repo removes it as safety)
git remote add origin https://github.com/you/repo.git

# 4. Force push
git push --force --all

# 5. ROTATE ALL EXPOSED CREDENTIALS ← most important!
#    Even after scrubbing history, anyone who cloned before
#    the fix still has the secrets.
```

---

## The Zombie Leak Problem

A "Zombie Leak" happens when you delete a commit or make a repo private **without revoking the secret**:

1. Developer pushes `.env` with real secrets
2. Realizes mistake, removes file, pushes fix
3. Thinks it's safe — **but git history preserves everything**
4. Attacker runs `git log -p` or browses GitHub commit diff
5. Gets all secrets, uses them months/years later

**Real example:** Toyota had a credential exposed on GitHub for **5 years** before a breach occurred.

90% of secrets are still valid 5 days after being leaked. Only 2.6% are revoked within an hour.

---

## Prevention Checklist

- [ ] Add `.env` to `.gitignore` **before** your first commit
- [ ] Use `.env.example` with placeholder values only
- [ ] Install the pre-commit hook from this repo
- [ ] Enable GitHub Secret Scanning on your repos
- [ ] Never commit real secrets — use environment variables at runtime
- [ ] If using AI coding agents: always check generated `.gitignore`
- [ ] Audit existing repos with `scan_repos.sh`

---

## Files in This Repo

| File | Purpose |
|------|---------|
| `leak_radar.py` | Real-time GitHub scanner with notifications |
| `notify.py` | Notification module (email, issue, print) |
| `scan_repos.sh` | Bash scanner for local git repos |
| `pre-commit` | Git hook to block `.env` commits |
| `env.gitignore` | Universal `.gitignore` template for env files |

---

## Why I Built This

I committed `.env` files to 4 of my own repos. Real secrets — OpenAI keys, database passwords, bot tokens. I pushed a "fix" that just removed the files from tracking. Then I realized the commit diff on GitHub literally showed the secrets in plain text for anyone to see.

So I built this tool, scrubbed my own history properly, and now I'm sharing it so others can avoid the same mistake.

If this tool helped you, star the repo. If you found your secrets with it — rotate them immediately.

— [Ossama Taha](https://github.com/OssamaTaha)

---

*Data sourced live from GitHub Code Search API. Stats updated on each scan.*
