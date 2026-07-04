"""
VaultScan — patterns.py
Regex patterns for every type of secret we scan for.
Each pattern has a name, severity, and a description
explaining why it's dangerous if leaked.
"""

import re

# Each entry: (name, severity, description, compiled_regex)
# severity: critical / high / medium / low

PATTERNS = [
    # ── Cloud providers ──────────────────────────────────────────────────────
    (
        "AWS Access Key",
        "critical",
        "AWS access key — gives programmatic access to your AWS account",
        re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "AWS Secret Key",
        "critical",
        "AWS secret key — used alongside access key to sign API requests",
        re.compile(r"(?i)aws[_\-\s\.]*secret[_\-\s\.]*(?:access[_\-\s\.]*)?key[\s]*[=:\"'`]+\s*([A-Za-z0-9/+]{40})"),
    ),
    (
        "GCP API Key",
        "critical",
        "Google Cloud Platform API key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    (
        "GCP Service Account",
        "high",
        "Google service account credential JSON",
        re.compile(r'"type"\s*:\s*"service_account"'),
    ),
    (
        "Azure Storage Key",
        "critical",
        "Azure storage account key — full access to blob/table/queue storage",
        re.compile(r"(?i)(?:azure|storage)[_\-\s\.]*(?:account[_\-\s\.]*)?key[\s]*[=:\"'`]+\s*([A-Za-z0-9+/]{88}==)"),
    ),

    # ── Auth & identity ──────────────────────────────────────────────────────
    (
        "GitHub Token",
        "critical",
        "GitHub personal access token — can read/write your repos, delete code",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ),
    (
        "GitHub OAuth Token",
        "critical",
        "GitHub OAuth token",
        re.compile(r"gho_[A-Za-z0-9]{36}"),
    ),
    (
        "GitLab Token",
        "critical",
        "GitLab personal access token",
        re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    ),
    (
        "Anthropic API Key",
        "critical",
        "Anthropic/Claude API key — billed usage on your account",
        re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"),
    ),
    (
        "OpenAI API Key",
        "critical",
        "OpenAI API key — access to GPT models, billed to your account",
        re.compile(r"sk-[A-Za-z0-9]{32,}(?:T3BlbkFJ[A-Za-z0-9]{32,})?"),
    ),
    (
        "HuggingFace Token",
        "high",
        "HuggingFace API token — access to models and datasets",
        re.compile(r"hf_[A-Za-z0-9]{34,}"),
    ),

    # ── Payment & finance ────────────────────────────────────────────────────
    (
        "Stripe Secret Key",
        "critical",
        "Stripe secret key — can charge customers, issue refunds, see transactions",
        re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    ),
    (
        "Stripe Test Key",
        "medium",
        "Stripe test key — low risk but indicates patterns for finding real keys",
        re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
    ),
    (
        "Stripe Publishable Key",
        "low",
        "Stripe publishable key — public-facing but worth flagging",
        re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
    ),
    (
        "PayPal Client Secret",
        "critical",
        "PayPal OAuth client secret",
        re.compile(r"(?i)paypal[_\-\s\.]*(?:client[_\-\s\.]*)?secret[\s]*[=:\"'`]+\s*([A-Za-z0-9\-_]{20,})"),
    ),

    # ── Communication services ───────────────────────────────────────────────
    (
        "Twilio API Key",
        "critical",
        "Twilio credentials — can send SMS/calls billed to your account",
        re.compile(r"SK[a-z0-9]{32}"),
    ),
    (
        "Twilio Account SID",
        "high",
        "Twilio Account SID — identifies your account",
        re.compile(r"AC[a-z0-9]{32}"),
    ),
    (
        "SendGrid API Key",
        "critical",
        "SendGrid key — can send bulk email from your account",
        re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
    ),
    (
        "Mailgun API Key",
        "critical",
        "Mailgun API key — email sending and account access",
        re.compile(r"key-[0-9a-zA-Z]{32}"),
    ),
    (
        "Mailchimp API Key",
        "high",
        "Mailchimp key — access to mailing lists and campaigns",
        re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ),
    (
        "Slack Bot Token",
        "high",
        "Slack bot token — can read messages, post to channels",
        re.compile(r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}"),
    ),
    (
        "Slack User Token",
        "high",
        "Slack user token — acts as a real user in your workspace",
        re.compile(r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{32}"),
    ),
    (
        "Slack Webhook",
        "medium",
        "Slack incoming webhook — can post messages to a channel",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    (
        "Discord Bot Token",
        "high",
        "Discord bot token — can control your bot",
        re.compile(r"[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}"),
    ),
    (
        "Discord Webhook",
        "medium",
        "Discord webhook — can post messages to a server channel",
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
    ),

    # ── Databases ────────────────────────────────────────────────────────────
    (
        "Database URL (generic)",
        "critical",
        "Full database connection string — includes host, credentials, and DB name",
        re.compile(
            r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlite)"
            r"://[^:@\s\"'`]+:[^@\s\"'`]+@[^\s\"'`/]+"
        ),
    ),
    (
        "MongoDB Connection",
        "critical",
        "MongoDB Atlas connection string with embedded credentials",
        re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"'`]+"),
    ),

    # ── Hardcoded passwords ──────────────────────────────────────────────────
    (
        "Hardcoded Password",
        "high",
        "Plaintext password assignment in code",
        re.compile(
            r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*[\"'`]([^\"'`\s]{6,})[\"'`]"
        ),
    ),
    (
        "Hardcoded Secret",
        "high",
        "Generic secret or key assignment",
        re.compile(
            r"(?i)(?:secret|api_key|apikey|auth_token|access_token|private_key)"
            r"\s*[=:]\s*[\"'`]([^\"'`\s]{8,})[\"'`]"
        ),
    ),

    # ── Tokens & keys ────────────────────────────────────────────────────────
    (
        "JWT Token",
        "medium",
        "JSON Web Token — may contain sensitive claims or be used for auth bypass",
        re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"),
    ),
    (
        "Private Key (PEM)",
        "critical",
        "RSA/EC private key — can decrypt data or impersonate servers",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "SSH Private Key",
        "critical",
        "SSH private key — allows server login without a password",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ),
    (
        "Certificate",
        "low",
        "SSL/TLS certificate — usually public but worth noting",
        re.compile(r"-----BEGIN CERTIFICATE-----"),
    ),
    (
        "NPM Auth Token",
        "high",
        "NPM registry auth token — can publish packages as you",
        re.compile(r"(?://registry\.npmjs\.org/:_authToken=|NPM_TOKEN\s*[=:]\s*)[A-Za-z0-9\-_]{36,}"),
    ),

    # ── Analytics & monitoring ───────────────────────────────────────────────
    (
        "Firebase Config",
        "high",
        "Firebase API key — access to Firebase services",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    (
        "Sentry DSN",
        "medium",
        "Sentry DSN — reveals your Sentry org and project IDs",
        re.compile(r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+"),
    ),
    (
        "Datadog API Key",
        "high",
        "Datadog API key — access to metrics, logs, and monitors",
        re.compile(r"(?i)datadog[_\-\s\.]*(?:api[_\-\s\.]*)?key[\s]*[=:\"'`]+\s*([a-f0-9]{32})"),
    ),

    # ── High-entropy string detector ─────────────────────────────────────────
    # Catches things the above patterns might miss
    (
        "High-entropy string",
        "medium",
        "Random-looking string assigned to a sensitive variable — likely a secret",
        re.compile(
            r"(?i)(?:token|key|secret|password|credential|auth)"
            r"\s*[=:]\s*[\"'`]([A-Za-z0-9+/=\-_]{32,})[\"'`]"
        ),
    ),
]

# File extensions to skip (binary / media / generated)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".pyc", ".pyo", ".class", ".so", ".dll", ".exe",
    ".lock",  # package-lock, poetry.lock — too noisy
    ".min.js", ".min.css",
}

# File names that almost always contain false positives
SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "composer.lock",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
}

# Lines that look like secrets but almost never are
FALSE_POSITIVE_HINTS = [
    "example",
    "your_",
    "YOUR_",
    "xxxx",
    "XXXX",
    "placeholder",
    "changeme",
    "replace",
    "xxxxxxxx",
    "<",
    ">",
    "...",
    "todo",
    "TODO",
    "fake",
    "dummy",
    "test123",
    "password123",
    "insert_",
    "put_your",
]
