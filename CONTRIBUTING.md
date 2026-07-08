# Contributing to VaultScan 🔍

Thanks for contributing! VaultScan is a security tool — contributions that improve detection accuracy, reduce false positives, or add new secret patterns are especially high value.

---

## What we'd love help with

- **New secret patterns** — new services, API key formats, token prefixes (see list below)
- **False positive reduction** — patterns that fire too aggressively in real repos
- **Performance** — large repos with thousands of commits can be slow; improvements welcome
- **Output formats** — HTML report, markdown summary, GitHub Actions integration
- **`--fix` mode** — automatically add detected files to `.gitignore`
- **Tests** — unit tests using crafted git repos with known secrets

---

## Setting up locally

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/vaultscan.git
cd vaultscan

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install in editable mode
pip install -e .

# 4. Confirm the command works
vaultscan --help

# 5. Test against a real repo
cd /path/to/any/git/repo
vaultscan .
```

---

## Project structure

```
vaultscan/
├── vaultscan_pkg/
│   ├── __init__.py
│   ├── patterns.py     ← all regex patterns for secret detection
│   ├── scanner.py      ← git history walker and detection engine
│   ├── report.py       ← terminal and JSON report renderer
│   └── cli.py          ← vaultscan command entry point
├── pyproject.toml
├── requirements.txt
└── README.md
```

**Data flow:**
```
cli.py  →  scanner.py (walks git history)  →  patterns.py (matches secrets)  →  report.py (renders output)
```

---

## Adding a new secret pattern

All patterns live in `vaultscan_pkg/patterns.py` inside the `PATTERNS` list. Each entry is a tuple:

```python
(
    "Pattern Name",      # shown in the report
    "severity",          # critical / high / medium / low
    "Description",       # explains the risk if this leaks
    re.compile(r"..."),  # the regex
)
```

**How to write a good pattern:**

1. Find a real example of the secret format (check the service's docs or GitHub for leaked examples)
2. Write the tightest regex that matches it — avoid being too broad
3. Test it doesn't match obvious placeholders like `YOUR_KEY_HERE`

Example — adding a Cloudflare API token:

```python
(
    "Cloudflare API Token",
    "critical",
    "Cloudflare API token — can modify DNS, firewall rules, and SSL certs",
    re.compile(r"[A-Za-z0-9_-]{40}"),   # Cloudflare tokens are 40 chars
),
```

Add it to `PATTERNS` in the appropriate category (Cloud providers, Auth, Payment, etc.)

**Testing your pattern:**

```bash
# Create a test file with a fake secret
echo 'CF_TOKEN="abc123defghijklmnopqrstuvwxyz0123456789AB"' > /tmp/test.txt

# Quick test in Python
python3 -c "
from vaultscan_pkg.patterns import PATTERNS
import re
line = 'CF_TOKEN=\"abc123defghijklmnopqrstuvwxyz0123456789AB\"'
for name, sev, desc, pattern in PATTERNS:
    if pattern.search(line):
        print(f'MATCH: {name}')
"
```

---

## Adding a false positive filter

If a pattern fires on things it shouldn't (e.g. test/example values), add hints to `FALSE_POSITIVE_HINTS` in `patterns.py`:

```python
FALSE_POSITIVE_HINTS = [
    "example",
    "your_",
    "YOUR_",
    "xxxx",
    # Add yours here:
    "my_new_hint",
]
```

Lines containing any of these strings are skipped before pattern matching.

---

## Working on the scanner (scanner.py)

The scanner walks git history using `git log` and `git show` via subprocess — no external git libraries needed. Key functions:

| Function | What it does |
|---|---|
| `get_all_commits()` | Returns every commit hash, author, date, and message |
| `get_commit_diff()` | Gets the unified diff for one commit |
| `parse_packet()` | Runs all patterns against a block of text |
| `scan_repo()` | Orchestrates the full scan and deduplicates findings |

**Deduplication** — the same secret appearing in 10 commits is reported once, identified by `pattern_name + first 40 chars of match`. If you add a new scan source, use the same `fingerprint()` mechanism to avoid duplicate findings.

---

## Making a change

```bash
git checkout -b feat/add-cloudflare-pattern

# Edit vaultscan_pkg/patterns.py
# Test your change:
cd /path/to/any/git/repo
vaultscan .

# Also test JSON output is still valid:
vaultscan --json 2>/dev/null | python3 -m json.tool > /dev/null && echo "JSON OK"

git add vaultscan_pkg/patterns.py
git commit -m "feat: add Cloudflare API token pattern"
git push origin feat/add-cloudflare-pattern
```

---

## Commit message format

```
type: short description

Examples:
feat: add Cloudflare API token and Global API key patterns
fix: JWT pattern matching base64url padding incorrectly
docs: add pre-commit hook setup to README
refactor: split scan_text into smaller helper functions
test: add fixture repo with known AWS key in history
```

Types: `feat` `fix` `docs` `refactor` `test`

---

## Pull request checklist

- [ ] `vaultscan --help` runs without errors
- [ ] New pattern tested against a real example of that secret format
- [ ] New pattern does NOT fire on `YOUR_KEY_HERE`, `example`, `xxxx` style placeholders
- [ ] `vaultscan --json 2>/dev/null | python3 -m json.tool` passes (valid JSON)
- [ ] No existing patterns broken (test against a repo with known secrets)
- [ ] Commit message follows the format above
- [ ] Pattern added to the correct category in `patterns.py` with a clear description

---

## Responsible disclosure

If you discover a real secret while testing VaultScan against public repos, please report it to the repo owner privately — not in a VaultScan issue. Don't publish or use discovered credentials.

---

## Questions?

Open a [GitHub Issue](https://github.com/kazim-45/vaultscan/issues) and tag it `question`.

MIT Licensed — contributions are welcome from everyone.
