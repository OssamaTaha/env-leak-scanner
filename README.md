# 🚨 The .env Leak Crisis on GitHub

## The Problem

You commit a `.env` file, realize your mistake, remove it, and push a fix. **You think it's over. It's not.**

The secrets are **permanently in your git history**. Anyone can run `git log -p` or browse your commit diffs on GitHub and see exactly what was in that file — including all your API keys, passwords, and tokens.

## The Numbers (2024 Data)

| Metric | Count |
|--------|-------|
| New secrets leaked on public GitHub (2024) | **23.7 million** (+25% YoY) |
| Commits containing at least one secret | **8 million** |
| Repositories that leaked a secret | **3 million** |
| Developers who leaked a secret | **1 in 10** |
| Secrets still valid 5 days after leak | **90%** |
| Secrets revoked within 1 hour of notification | **2.6%** |

**Source:** GitGuardian State of Secrets Sprawl 2025 Report

## Most Leaked Secret Types

- **OpenAI API Keys** — 1,212% increase in 2024 (GenAI boom)
- **Google API Keys** — 1M+ valid secrets exposed
- **AWS Credentials** — 140K+ valid secrets exposed
- **Database URLs** (PostgreSQL, MongoDB)
- **Stripe Payment Keys**
- **Discord/Telegram Bot Tokens**
- **JWT Secrets**

## The "Zombie Leak" Problem

When you delete a commit or make a repo private **without revoking the secret**, it becomes a "Zombie Leak":

1. Developer pushes `.env` with real secrets
2. Realizes mistake, removes file, pushes fix
3. Thinks it's safe — **but git history preserves everything**
4. Attacker runs `git log -p` or browses GitHub commit diff
5. Gets all secrets, uses them months/years later

**Real example:** Toyota had a credential exposed on GitHub for **5 years** before a breach occurred.

## Why "git rm .env" Doesn't Fix It

```bash
# This ONLY removes from future commits
git rm .env
git commit -m "remove .env"
git push

# But anyone can still see the secret:
git log -p -- .env
# Shows: -DATABASE_PASSWORD=supersecret123
```

The `-` in the diff shows the deleted line — including your secrets. On GitHub, this is visible in the "Files changed" tab of any commit that touched the file.

## How to ACTUALLY Fix It

### Step 1: Scrub Git History
```bash
# Install git-filter-repo
pip install git-filter-repo

# Remove .env from ALL history
git filter-repo --invert-paths --path .env

# Re-add remote (filter-repo removes it as safety)
git remote add origin https://github.com/you/repo.git

# Force push
git push --force --all
```

### Step 2: Update .gitignore
```gitignore
# Environment files
.env
.env.local
.env.*.local
.env.production
.env.staging
*.env
compose.env
```

### Step 3: ROTATE ALL EXPOSED CREDENTIALS
**This is the most important step.** Even after scrubbing history:
- Anyone who cloned before the fix still has the secrets
- GitGuardian and other scanners may have already indexed them
- Cached CDN responses on GitHub may persist briefly

Change your:
- API keys (OpenAI, AWS, Stripe, etc.)
- Database passwords
- Bot tokens
- JWT secrets
- Any other credential that was in the file

### Step 4: Create .env.example
```bash
# .env.example (safe to commit)
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
OPENAI_API_KEY=your_openai_key_here
SECRET_KEY=your_secret_key_here
```

## Scanner Tool

Run this to check your own repos:

```bash
# Download and run
curl -sSL https://raw.githubusercontent.com/OssamaTaha/env-leak-scanner/main/scan_repos.sh | bash

# Or clone and run locally
git clone https://github.com/OssamaTaha/env-leak-scanner.git
cd env-leak-scanner
chmod +x scan_repos.sh
./scan_repos.sh /path/to/your/projects
```

## Prevention Checklist

- [ ] Add `.env` to `.gitignore` **before** your first commit
- [ ] Use `.env.example` with placeholder values
- [ ] Enable GitHub Secret Scanning on your repos
- [ ] Use a secrets manager (Vault, AWS Secrets Manager, etc.)
- [ ] Never hardcode secrets — use environment variables
- [ ] Pre-commit hooks to block `.env` commits
- [ ] Regular audits with tools like `gitleaks` or `trufflehog`

## Resources

- [GitGuardian State of Secrets Sprawl 2025](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)

---

*Created by [Ossama Taha](https://github.com/OssamaTaha) after learning this lesson the hard way. Don't be like me.*
