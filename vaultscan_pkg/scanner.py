"""
VaultScan — scanner.py
Git history scanning engine. Uses `git log` and `git show`
to walk every commit, diff, and file — without modifying
your repo or needing any external dependencies beyond git.
"""

import subprocess
import os
import re
from pathlib import Path
from collections import defaultdict
from .patterns import PATTERNS, SKIP_EXTENSIONS, SKIP_FILENAMES, FALSE_POSITIVE_HINTS


# ── Git helpers ───────────────────────────────────────────────────────────────

def run_git(args: list, cwd: str) -> str:
    """Run a git command and return stdout. Returns '' on error."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def is_git_repo(path: str) -> bool:
    out = run_git(["rev-parse", "--is-inside-work-tree"], path)
    return out.strip() == "true"


def get_repo_root(path: str) -> str:
    out = run_git(["rev-parse", "--show-toplevel"], path)
    return out.strip()


def get_all_commits(repo: str) -> list:
    """Return list of (hash, short_hash, author, date, subject) for every commit."""
    out = run_git([
        "log", "--all",
        "--format=%H|||%h|||%an|||%ad|||%s",
        "--date=short",
    ], repo)
    commits = []
    for line in out.strip().splitlines():
        parts = line.split("|||", 4)
        if len(parts) == 5:
            commits.append({
                "hash":    parts[0],
                "short":   parts[1],
                "author":  parts[2],
                "date":    parts[3],
                "subject": parts[4],
            })
    return commits


def get_commit_diff(repo: str, commit_hash: str) -> str:
    """Get the unified diff for a single commit."""
    # For the first commit, diff against empty tree
    out = run_git(["show", "--no-color", "-U0", commit_hash], repo)
    return out


def get_current_files(repo: str) -> list:
    """List all tracked files in the current working tree."""
    out = run_git(["ls-files"], repo)
    return [f.strip() for f in out.splitlines() if f.strip()]


def get_file_content(repo: str, filepath: str) -> str:
    """Read a file's current content from HEAD."""
    out = run_git(["show", f"HEAD:{filepath}"], repo)
    return out


# ── Secret detection ──────────────────────────────────────────────────────────

class Finding:
    __slots__ = (
        "pattern_name", "severity", "description",
        "match", "line", "line_no",
        "commit_hash", "commit_short", "commit_date",
        "commit_author", "commit_subject",
        "filepath", "source",
    )

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def fingerprint(self):
        """Unique key to deduplicate the same secret across commits."""
        return f"{self.pattern_name}::{self.match[:40]}"


def should_skip_file(filepath: str) -> bool:
    name = Path(filepath).name
    if name in SKIP_FILENAMES:
        return True
    for ext in SKIP_EXTENSIONS:
        if filepath.endswith(ext):
            return True
    return False


def is_false_positive(line: str) -> bool:
    for hint in FALSE_POSITIVE_HINTS:
        if hint in line:
            return True
    return False


def scan_text(text: str, filepath: str = "", commit: dict = None) -> list:
    """
    Run all patterns against a block of text.
    Returns list of Finding objects.
    """
    findings = []
    seen_in_block = set()

    for line_no, line in enumerate(text.splitlines(), 1):
        # Skip diff header lines
        if line.startswith("diff --git") or line.startswith("index ") \
                or line.startswith("---") or line.startswith("+++") \
                or line.startswith("@@"):
            continue

        # Only scan added lines in diffs (lines starting with +)
        # For current-file scans, scan everything
        if text.startswith("diff") and not line.startswith("+"):
            continue

        # Strip the leading + from diff lines
        scan_line = line[1:] if line.startswith("+") else line

        if is_false_positive(scan_line):
            continue

        for name, severity, description, pattern in PATTERNS:
            try:
                match = pattern.search(scan_line)
            except Exception:
                continue

            if not match:
                continue

            matched_text = match.group(0)

            # Deduplicate within this block
            key = f"{name}::{matched_text[:40]}"
            if key in seen_in_block:
                continue
            seen_in_block.add(key)

            finding = Finding(
                pattern_name   = name,
                severity       = severity,
                description    = description,
                match          = matched_text,
                line           = scan_line.strip()[:200],
                line_no        = line_no,
                filepath       = filepath,
                source         = "history" if commit else "working_tree",
                commit_hash    = commit["hash"]    if commit else None,
                commit_short   = commit["short"]   if commit else None,
                commit_date    = commit["date"]     if commit else None,
                commit_author  = commit["author"]  if commit else None,
                commit_subject = commit["subject"] if commit else None,
            )
            findings.append(finding)

    return findings


# ── Main scan orchestrator ────────────────────────────────────────────────────

def scan_repo(
    repo_path: str,
    scan_history: bool = True,
    scan_current: bool = True,
    on_progress=None,
) -> dict:
    """
    Full repo scan. Returns a result dict.
    on_progress(message, current, total) is called as we go.
    """

    results = {
        "repo":        repo_path,
        "findings":    [],
        "commits_scanned": 0,
        "files_scanned":   0,
        "errors":      [],
    }

    seen_fingerprints = set()

    def add_finding(f: Finding):
        fp = f.fingerprint()
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            results["findings"].append(f)

    # ── Scan git history ──────────────────────────────────────────────────
    if scan_history:
        commits = get_all_commits(repo_path)
        total   = len(commits)

        for i, commit in enumerate(commits):
            if on_progress:
                on_progress(
                    f"Scanning commit {commit['short']} ({commit['date']})",
                    i + 1, total,
                )

            diff = get_commit_diff(repo_path, commit["hash"])
            if not diff:
                continue

            results["commits_scanned"] += 1

            # Split diff into per-file sections
            current_file = ""
            for line in diff.splitlines():
                if line.startswith("diff --git"):
                    # Extract filename: "diff --git a/foo.py b/foo.py"
                    parts = line.split(" b/", 1)
                    current_file = parts[1] if len(parts) == 2 else ""

                if should_skip_file(current_file):
                    continue

            # Scan the whole diff in one pass for simplicity
            file_findings = scan_text(diff, filepath="(git diff)", commit=commit)
            for f in file_findings:
                add_finding(f)

    # ── Scan current working tree ──────────────────────────────────────────
    if scan_current:
        files = get_current_files(repo_path)
        total_files = len(files)

        for i, filepath in enumerate(files):
            if should_skip_file(filepath):
                continue

            if on_progress:
                on_progress(
                    f"Scanning file {filepath}",
                    i + 1, total_files,
                )

            content = get_file_content(repo_path, filepath)
            if not content:
                continue

            results["files_scanned"] += 1
            file_findings = scan_text(content, filepath=filepath, commit=None)
            for f in file_findings:
                add_finding(f)

    # Sort: critical first, then high, medium, low
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results["findings"].sort(key=lambda f: sev_order.get(f.severity, 4))

    return results
