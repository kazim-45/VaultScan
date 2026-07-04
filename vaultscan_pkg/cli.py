"""
VaultScan — cli.py
Entry point registered as the `vaultscan` command.
"""

import sys
import os
import argparse
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="vaultscan",
        description="VaultScan — scan git history for accidentally committed secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vaultscan                        Scan current directory
  vaultscan /path/to/repo          Scan a specific repo
  vaultscan --no-history           Only scan current files (faster)
  vaultscan --no-current           Only scan git history
  vaultscan --json                 Output as JSON (pipe-friendly)
  vaultscan --json report.json     Save JSON report to file
  vaultscan --all                  Show all findings (default: cap at 50)
  vaultscan --severity critical    Only show critical findings

Severity levels: critical, high, medium, low
        """,
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Path to the git repository (default: current directory)",
    )
    parser.add_argument(
        "--no-history", action="store_true",
        help="Skip git history — only scan current working tree",
    )
    parser.add_argument(
        "--no-current", action="store_true",
        help="Skip current files — only scan git history",
    )
    parser.add_argument(
        "--json", nargs="?", const="-", metavar="OUTPUT",
        help="Output as JSON (optionally save to file)",
    )
    parser.add_argument(
        "--all", dest="show_all", action="store_true",
        help="Show all findings (default caps at 50 in terminal mode)",
    )
    parser.add_argument(
        "--severity", choices=["critical", "high", "medium", "low"],
        help="Only report findings at or above this severity",
    )
    args = parser.parse_args()

    # ── Validate repo path ────────────────────────────────────────────────
    from .scanner import is_git_repo, get_repo_root, scan_repo
    from .report  import render_terminal, render_json

    repo_path = str(Path(args.path).resolve())

    if not os.path.isdir(repo_path):
        console.print(f"[red]Not a directory:[/] {repo_path}")
        sys.exit(1)

    if not is_git_repo(repo_path):
        console.print(f"[red]Not a git repository:[/] {repo_path}")
        console.print("[dim]Initialise with  git init  or point to an existing repo.[/]")
        sys.exit(1)

    repo_root = get_repo_root(repo_path)
    json_mode = args.json is not None
    err = Console(stderr=True) if json_mode else console

    err.print()
    err.print(f"[dim]Repository: [bold]{repo_root}[/][/]")

    scan_history = not args.no_history
    scan_current = not args.no_current

    if not scan_history and not scan_current:
        console.print("[red]Error:[/] --no-history and --no-current both set — nothing to scan.")
        sys.exit(1)

    # ── Run scan with progress bar ────────────────────────────────────────
    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}[/]"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=err,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        def on_progress(msg, current, total):
            progress.update(task, description=msg, total=total, completed=current)

        results = scan_repo(
            repo_root,
            scan_history=scan_history,
            scan_current=scan_current,
            on_progress=on_progress,
        )

    # ── Filter by severity if requested ──────────────────────────────────
    if args.severity:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = order[args.severity]
        results["findings"] = [
            f for f in results["findings"]
            if order.get(f.severity, 99) <= threshold
        ]

    # ── Output ────────────────────────────────────────────────────────────
    if json_mode:
        output_file = None if args.json == "-" else args.json
        render_json(results, output_file)
    else:
        render_terminal(results, show_all=args.show_all)


if __name__ == "__main__":
    main()
