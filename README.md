# VaultScan 🔍

**Scan your entire git history for accidentally committed secrets.**

Checks every commit your repo has ever had — not just current files — for API keys, passwords, tokens, and credentials. Because deleting a file doesn't remove it from git history, and leaked secrets get scraped within minutes of being pushed.

```
$ vaultscan

VaultScan  v1.0
Git history secret scanner
Repo: /home/kazim/projects/myapp

  Commits scanned   47
  Files scanned     12
  Secrets found     3
  Severity          🔴 1 critical  🟠 2 high

🔴 [CRITICAL]  AWS Access Key
   AWS access key — gives programmatic access to your AWS account
   Match:  AKIAIO********************…
   Commit: a3f9b12  2024-03-15  kazim
   Msg:    "add deployment config"

🔴 [CRITICAL]  Database URL (generic)
   Full database connection string with credentials
   Match:  postgre********************…
   Commit: 18d09e3  2024-02-01  kazim
   Msg:    "remove .env oops"
```

---

## Why this matters

When you commit a secret and push it to GitHub, it's exposed — even if you delete it in the next commit. Git keeps the full history, and automated bots continuously scrape GitHub looking for credentials. AWS keys get found and abused within seconds of being pushed.

VaultScan catches:
- Secrets you added intentionally and forgot to remove
- Secrets that slipped through in a `.env` file you meant to `.gitignore`
- Secrets buried in commits from months or years ago

---

## Installation

```bash
git clone https://github.com/kazim-45/vaultscan.git
cd vaultscan
pip install -e .
```

---

## Usage

```bash
# Scan the current directory (must be a git repo)
vaultscan

# Scan a specific repo
vaultscan /path/to/repo

# Only scan current files — much faster, skips history
vaultscan --no-history

# Only scan git history — skip current working tree
vaultscan --no-current

# Only show critical findings
vaultscan --severity critical

# Show all findings (default caps at 50 in terminal)
vaultscan --all

# Export as JSON
vaultscan --json

# Save JSON report to a file
vaultscan --json report.json

# Pipe-friendly (progress goes to stderr, JSON to stdout)
vaultscan --json | jq '.findings[] | select(.severity=="critical")'

# Help
vaultscan --help
```

---

## What it detects

| Category | Examples |
|---|---|
| AWS | Access keys, secret keys |
| Google Cloud | GCP API keys, service account credentials |
| Azure | Storage account keys |
| GitHub / GitLab | Personal access tokens, OAuth tokens |
| AI APIs | OpenAI, Anthropic/Claude, HuggingFace |
| Payment | Stripe live/test keys, PayPal secrets |
| Communication | Twilio, SendGrid, Mailgun, Mailchimp |
| Chat | Slack tokens & webhooks, Discord tokens & webhooks |
| Databases | Full connection strings (Postgres, MySQL, MongoDB, Redis) |
| Auth | Private keys (PEM/RSA/EC), SSH keys, JWT tokens |
| NPM | Registry auth tokens |
| Monitoring | Sentry DSN, Datadog keys |
| Generic | Hardcoded passwords, high-entropy secret assignments |

35+ patterns across all major services.

---

## How it works

VaultScan uses `git log` and `git show` to walk every commit in your repo's history. For each commit it reads the diff — the lines that were added or removed — and runs 35+ regex patterns against them. It also scans your current working tree separately.

**Why diffs, not file snapshots?** Reading diffs catches secrets that were added and then deleted. If you committed `AWS_KEY=AKIA...` three months ago and deleted it the next day, the deletion commit's diff shows `-AWS_KEY=AKIA...` — VaultScan still catches it.

**False positive reduction:**
- Skips binary files, lock files, and generated assets
- Ignores lines containing known placeholder hints (`example`, `YOUR_KEY`, `xxxx`, `changeme`, etc.)
- Deduplicates — the same secret appearing across multiple commits is reported once

---

## What to do when you find something

**1. Revoke immediately.** Go to the service's dashboard and revoke/regenerate the credential. Assume it's already been found.

**2. Remove from git history.** Deleting the file isn't enough.

```bash
# Install git-filter-repo
pip install git-filter-repo

# Remove a specific file from all history
git filter-repo --path .env --invert-paths

# Force-push the rewritten history
git push --force --all
```

**3. Use environment variables from now on.** Store secrets in a `.env` file and add it to `.gitignore`. Load them in Python with `python-dotenv`:

```python
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("MY_API_KEY")
```

**4. Prevent it happening again.** Set up `detect-secrets` as a pre-commit hook so secrets are caught before they ever reach git:

```bash
pip install pre-commit detect-secrets
detect-secrets scan > .secrets.baseline
```

---

## Project structure

```
vaultscan/
├── vaultscan_pkg/
│   ├── __init__.py
│   ├── patterns.py    ← 35+ regex patterns for every secret type
│   ├── scanner.py     ← git history walking and detection engine
│   ├── report.py      ← terminal and JSON report renderer
│   └── cli.py         ← vaultscan command entry point
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Dependencies

- [`rich`](https://pypi.org/project/rich/) — terminal output
- Python stdlib only for everything else (`subprocess`, `re`, `json`, `pathlib`)
- Requires `git` to be installed (it already is on any dev machine)

---

## License

MIT — use it, fork it, build on it.

---

*Built by [kazim-45](https://github.com/kazim-45) — part of a cybersecurity CLI toolkit alongside [MetaHunter](https://github.com/kazim-45/MetaHunter), [PassAudit](https://github.com/kazim-45/passaudit), [LogWatch](https://github.com/kazim-45/logwatch), and [NetSpy](https://github.com/kazim-45/netspy).*
