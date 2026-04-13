# 🔒 .env Leak Radar

**Find exposed secrets in your GitHub repos. Before someone else does.**

Scans your GitHub repositories for `.env` files with hardcoded API keys, database passwords, and tokens — even ones you deleted but are still sitting in git history.

```
 ██╗     ███████╗ █████╗ ██╗  ██╗    ██████╗  █████╗ ██████╗  █████╗ ██████╗
 ██║     ██╔════╝██╔══██╗██║ ██╔╝    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗
 ██║     █████╗  ███████║█████╔╝     ██████╔╝███████║██║  ██║███████║██████╔╝
 ██║     ██╔══╝  ██╔══██║██╔═██╗     ██╔══██╗██╔══██║██║  ██║██╔══██║██╔══██╗
 ███████╗███████╗██║  ██║██║  ██╗    ██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║
 ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## Live GitHub Data

*Scanned April 13, 2026 — this tool queries GitHub's API in real-time.*

```
SECRET TYPE              EXPOSED     RISK
─────────────────────────────────────────────────────
JWT Secrets              13,228  ████████████████████████████████  🔴
Database URLs            12,816  ██████████████████████████████    🔴
MongoDB URIs              5,344  █████████████████                 🟠
Stripe Live Keys          2,984  ████████████                      🟠
AWS Credentials           2,544  ██████████                        🟠
Anthropic/Claude Keys     2,096  ████████                          🟡
OpenAI API Keys           1,704  ███████                           🟡
Google AI/Gemini          1,168  █████                             🟡
Discord Tokens            1,040  ████                              🟡
─────────────────────────────────────────────────────
TOTAL                    42,924
```

> **This is just the tip.** GitHub caps search at 1,000 results per query. The real number is 10-100x higher.

### Historical Context

| Year | New Secrets Leaked | Source |
|------|-------------------|--------|
| 2023 | 12.8 million | GitGuardian |
| 2024 | **23.7 million** (+25%) | GitGuardian |
| 2026 | Est. **50-80 million** | Coding agents + vibe coders |

The explosion in 2025-2026 is driven by AI coding tools (Cursor, Claude Code, Copilot) generating `.env` files for every new project — and non-developers pushing them without understanding git.

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

### The "Zombie Leak"

1. You push `.env` with real secrets
2. Realize mistake, remove file, push fix
3. Think it's safe — **but git history preserves everything**
4. Attacker runs `git log -p` months later
5. Gets all your secrets

**Toyota** had a credential exposed on GitHub for **5 years** before a breach. **90% of secrets are still valid** 5 days after being leaked.

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

## Why 2026 Is Worse

Before AI coding assistants, developers at least knew about `.gitignore`. Now:

- **Cursor/Claude Code/Copilot** generate `.env` files automatically
- **Vibe coders** (designers, founders, students) build apps without git knowledge
- **AI tutorials** show "create .env" but never mention `.gitignore`
- **Copy-paste culture** — AI says "run this" and people run it

The result: millions of new public repos with exposed secrets, created by people who don't know they leaked anything.

---

## Files

| File | Purpose |
|------|---------|
| `scan_repos.sh` | Scan your local git repos for leaked secrets |
| `pre-commit` | Git hook to block `.env` commits |
| `env.gitignore` | Universal `.gitignore` template |
| `leak_radar.py` | GitHub API scanner (for research) |
| `daemon.py` | Continuous monitoring service |

---

*Built after I leaked secrets in 4 of my own repos and realized the "fix" commit showed them in plain text on GitHub. Don't be like me.*

— [Ossama Taha](https://github.com/OssamaTaha)
