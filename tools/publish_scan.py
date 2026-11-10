#!/usr/bin/env python3
"""publish_scan.py - block secrets and personal data from reaching the public repo.

Why: this repository is prepared for public release. Findings are published; the
operator's identity, device identifiers, tokens, local paths and private notes are not.

Usage:
    python tools/publish_scan.py --staged            # files staged for commit (pre-commit)
    python tools/publish_scan.py --all               # every tracked file
    python tools/publish_scan.py path [path ...]     # specific files
    python tools/publish_scan.py --staged --json out/publish_scan.json

Exit code: 0 = clean, 1 = findings (commit must be blocked), 2 = usage error.

Rules are intentionally explicit: a pattern that never fires on this project is
cheaper than one personal identifier leaking once.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

# Files that legitimately contain the patterns (the scanner itself, hook scripts).
ALLOWLIST = {
    "tools/publish_scan.py",
    ".githooks/pre-commit",
    ".gitignore",
}

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".bz2",
    ".xz", ".7z", ".ipsw", ".dmg", ".img", ".bin", ".o", ".so", ".dylib", ".a",
    ".pyc", ".class", ".jar", ".whl", ".exe", ".dll", ".kext",
}

MAX_BYTES = 2 * 1024 * 1024  # pre-commit refuses larger files anyway

# (rule name, regex, explanation)
RULES = [
    ("apple-serial", r"\b00008[0-9a-fA-F]{3}-[0-9a-fA-F]{16}\b",
     "Apple device serial / ECID"),
    ("apple-udid40", r"\b[0-9a-fA-F]{40}\b",
     "40-hex UDID-like identifier (verify it is not a hash)"),
    ("telegram-bot-token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
     "Telegram bot token"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}",
     "GitHub token"),
    ("openai-key", r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}",
     "API key (OpenAI / Anthropic style)"),
    ("aws-key", r"\bAKIA[0-9A-Z]{16}\b",
     "AWS access key id"),
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
     "private key block"),
    ("tailscale-host", r"\b[a-z0-9][a-z0-9-]*\.ts\.net\b",
     "Tailscale MagicDNS host name"),
    ("tailscale-ip", r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
     "Tailscale / CGNAT address"),
    ("windows-user-path", r"[A-Za-z]:\\+Users\\+[A-Za-z0-9._-]+",
     "absolute Windows user path"),
    ("wsl-user-path", r"/mnt/[a-z]/Users/[A-Za-z0-9._-]+",
     "WSL path into another user's profile"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "email address"),
    ("ru-phone", r"(?:\+7|\b8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b",
     "phone number"),
    ("credential-assign", r"(?i)\b(?:password|passwd|passphrase|pwd)\s*[:=]\s*\S{4,}",
     "password value in plain text"),
    ("secret-assign", r"(?i)\b(?:api[_-]?key|secret|token|bearer)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}",
     "secret/token value in plain text"),
    ("operator-identifiers", r"(?i)\b(?:EWWZNS|remontsuri|vladc|volyn|v\.eremin)\b",
     "operator handle, certificate or machine name"),
    ("personal-notes", r"(?i)^\s*(?:USER|SOUL)\.md\s*$",
     "personal profile document"),
]

COMPILED = [(name, re.compile(rx), why) for name, rx, why in RULES]

# Published documents must be English. Applied to Markdown only.
CYRILLIC = re.compile(r"[\u0400-\u04FF]")
MARKDOWN_EXT = {".md", ".markdown"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False).stdout


def staged_files() -> list[str]:
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR")
    return [p for p in out.splitlines() if p.strip()]


def tracked_files() -> list[str]:
    return [p for p in git("ls-files").splitlines() if p.strip()]


def is_binary(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in BINARY_EXT


def scan_file(path: str) -> list[dict]:
    hits: list[dict] = []
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return [{"path": path, "line": 0, "rule": "size", "why": "file larger than 2 MB"}]
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return [{"path": path, "line": 0, "rule": "io", "why": str(exc)}]

    for lineno, line in enumerate(lines, 1):
        for name, rx, why in COMPILED:
            m = rx.search(line)
            if m:
                snippet = m.group(0)
                if len(snippet) > 12:
                    snippet = snippet[:6] + "…" + snippet[-4:]
                hits.append({"path": path, "line": lineno, "rule": name,
                             "why": why, "match": snippet})
        if os.path.splitext(path)[1].lower() in MARKDOWN_EXT and CYRILLIC.search(line):
            hits.append({"path": path, "line": lineno, "rule": "language",
                         "why": "published documents must be English (Cyrillic found)",
                         "match": "", })
    return hits


def allowed(path: str) -> bool:
    norm = path.replace("\\", "/")
    base = os.path.basename(norm)
    return any(norm.endswith(entry) or base == os.path.basename(entry) for entry in ALLOWLIST)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Scan files for secrets and personal data")
    ap.add_argument("paths", nargs="*", help="explicit files to scan")
    ap.add_argument("--staged", action="store_true", help="scan files staged for commit")
    ap.add_argument("--all", action="store_true", help="scan every tracked file")
    ap.add_argument("--json", default=None, help="write findings as JSON to this path")
    ap.add_argument("--quiet", action="store_true", help="only print the summary")
    args = ap.parse_args(argv[1:])

    if args.staged:
        targets = staged_files()
    elif args.all:
        targets = tracked_files()
    elif args.paths:
        targets = args.paths
    else:
        ap.print_usage(sys.stderr)
        return 2

    targets = [p for p in targets if not allowed(p)]
    findings: list[dict] = []
    skipped = 0
    for path in targets:
        if not os.path.exists(path):
            continue
        if is_binary(path):
            skipped += 1
            continue
        findings.extend(scan_file(path))

    if not args.quiet:
        for f in findings:
            where = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
            print(f"BLOCK {where}  [{f['rule']}] {f['why']}"
                  + (f"  -> {f['match']}" if f.get("match") else ""))

    print(f"scanned {len(targets) - skipped} text files, skipped {skipped} binary, "
          f"findings {len(findings)}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"targets": targets, "findings": findings}, fh, indent=2, ensure_ascii=False)
        print(f"json -> {args.json}")

    if findings:
        print("RESULT: BLOCKED - remove or redact the lines above before committing.")
        return 1
    print("RESULT: CLEAN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
