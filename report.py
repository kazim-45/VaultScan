"""
VaultScan — report.py
Renders the scan results to the terminal using Rich,
or exports as JSON for piping into other tools.
"""

import json
from datetime import datetime
from collections import Counter
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich import box

console = Console()

SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
}
SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}
SEV_ORDER = ["critical", "high", "medium", "low"]


def _mask(value: str) -> str:
    """Show first 6 chars, mask the rest."""
    if len(value) <= 6:
        return "***"
    return value[:6] + "*" * min(len(value) - 6, 20) + "…"


def render_terminal(results: dict, show_all: bool = False):
    findings = results["findings"]
    sev_counts = Counter(f.severity for f in findings)

    console.print()
    console.print(Panel.fit(
        "[bold white]VaultScan[/]  [dim]v1.0[/]\n"
        "[dim]Git history secret scanner\n"
        f"Repo: {results['repo']}[/]",
        border_style="dim",
    ))

    # ── Summary ──
    console.print()
    console.rule("[bold]Scan Summary[/]")
    console.print()

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    t.add_column(style="dim", width=22)
    t.add_column()

    t.add_row("Commits scanned",  f"[bold]{results['commits_scanned']:,}[/]")
    t.add_row("Files scanned",    f"[bold]{results['files_scanned']:,}[/]")
    t.add_row("Secrets found",    f"[bold]{len(findings)}[/]")
    if findings:
        breakdown = "  ".join(
            f"[{SEV_COLOR[s]}]{SEV_ICON[s]} {sev_counts[s]} {s}[/]"
            for s in SEV_ORDER if sev_counts[s]
        )
        t.add_row("Severity", breakdown)

    console.print(t)

    if not findings:
        console.print(
            "  [green]✓ Clean — no secrets detected in this repo.[/]\n"
        )
        return

    # ── Findings ──
    console.print()
    console.rule("[bold]Findings[/]")

    displayed = 0
    for f in findings:
        if not show_all and displayed >= 50:
            remaining = len(findings) - displayed
            console.print(
                f"\n  [dim]… {remaining} more finding(s). "
                f"Run with [bold]--all[/] to see everything, "
                f"or use [bold]--json[/] to export.[/]"
            )
            break

        sev   = f.severity
        color = SEV_COLOR[sev]
        icon  = SEV_ICON[sev]

        console.print()
        console.print(
            f"  {icon} [{color}][{sev.upper()}][/]  "
            f"[bold]{f.pattern_name}[/]"
        )
        console.print(f"     [dim]{f.description}[/]")

        # What was found
        console.print(f"     [dim]Match:  [/][bold]{_mask(f.match)}[/]")

        # Where it is now
        if f.source == "working_tree":
            console.print(f"     [dim]File:   [/][yellow]{f.filepath}[/] [dim](current codebase)[/]")
        else:
            console.print(
                f"     [dim]Commit: [/][cyan]{f.commit_short}[/]  "
                f"[dim]{f.commit_date}  {f.commit_author}[/]"
            )
            console.print(
                f"     [dim]Msg:    [/][dim]\"{f.commit_subject[:60]}\"[/]"
            )

        # The offending line (truncated)
        line_preview = f.line[:120] + ("…" if len(f.line) > 120 else "")
        console.print(f"     [dim]Line:   [/][dim]{line_preview}[/]")

        displayed += 1

    # ── Remediation advice ──
    console.print()
    console.rule("[bold]What to do[/]")
    console.print()
    console.print(
        "  [bold]1. Revoke immediately[/]\n"
        "     Go to the service that issued the secret and revoke/regenerate it.\n"
        "     Assume it's already been found — leaked secrets get scraped within minutes.\n"
    )
    console.print(
        "  [bold]2. Remove from git history[/]\n"
        "     Deleting the file isn't enough — git keeps full history.\n"
        "     Use  [bold cyan]git filter-repo[/]  (recommended) or  [bold cyan]BFG Repo Cleaner[/]:\n"
        "       [dim]pip install git-filter-repo[/]\n"
        "       [dim]git filter-repo --path <file> --invert-paths[/]\n"
        "     Then force-push:  [dim]git push --force --all[/]\n"
    )
    console.print(
        "  [bold]3. Use environment variables from now on[/]\n"
        "     Store secrets in  [bold cyan].env[/]  files and add  [dim].env[/]  to  [dim].gitignore[/].\n"
        "     Load them with python-dotenv, dotenv (Node), or similar.\n"
    )
    console.print(
        "  [bold]4. Set up pre-commit scanning[/]\n"
        "     Install  [bold cyan]pre-commit[/]  +  [bold cyan]detect-secrets[/]  so secrets are\n"
        "     caught before they ever reach git:\n"
        "       [dim]pip install pre-commit detect-secrets[/]\n"
        "       [dim]detect-secrets scan > .secrets.baseline[/]\n"
    )
    console.print()


def render_json(results: dict, output_path: str = None):
    """Export findings as clean JSON."""
    data = {
        "generated_at":    datetime.now().isoformat(),
        "repo":            results["repo"],
        "commits_scanned": results["commits_scanned"],
        "files_scanned":   results["files_scanned"],
        "total_findings":  len(results["findings"]),
        "findings": [
            {
                "severity":       f.severity,
                "pattern":        f.pattern_name,
                "description":    f.description,
                "match_preview":  _mask(f.match),
                "source":         f.source,
                "filepath":       f.filepath,
                "commit_hash":    f.commit_hash,
                "commit_date":    f.commit_date,
                "commit_author":  f.commit_author,
                "commit_subject": f.commit_subject,
                "line_preview":   f.line[:120],
            }
            for f in results["findings"]
        ],
    }

    out = json.dumps(data, indent=2, default=str)
    if output_path:
        with open(output_path, "w") as fp:
            fp.write(out)
        console.print(f"[green]✓[/] JSON report saved → [bold]{output_path}[/]")
    else:
        print(out)
