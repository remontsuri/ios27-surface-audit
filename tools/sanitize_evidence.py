#!/usr/bin/env python3
"""sanitize_evidence.py - turn raw device logs into publishable evidence.

Raw logs contain what must not be published: absolute local paths, device identifiers,
relay host names, and (in this project) hex dumps of files the probe was allowed to read.
This script keeps the measurement lines and drops the rest.

    python tools/sanitize_evidence.py <input.log> <output.log> [--keep-prefix P ...]

Rules:
  * only lines starting with an allowed prefix survive (default: metric/result lines);
  * every line is passed through a redaction pass (paths, identifiers, hosts, tokens);
  * hex-dump lines (`00000000:`) and any line containing a long hex/ASCII blob are dropped.

The result is deterministic: same input -> same output, so a reader can diff it.
"""

from __future__ import annotations

import argparse
import io
import re
import sys

DEFAULT_PREFIXES = ("METRIC|", "W|", "E|", "VENDED", "TRAV", "AVEARR", "A_", "B_", "C_", "IFC", "RESULT")

# Redaction rules: (regex, replacement, comment)
REDACT = [
    (r"[A-Za-z]:\\+Users\\+[A-Za-z0-9._-]+", "<USERPROFILE>", "windows user path"),
    (r"[A-Za-z]:\\+[A-Za-z0-9._\\-]+", "<LOCALPATH>", "windows absolute path"),
    (r"/mnt/[a-z]/[A-Za-z0-9._/-]+", "<WSLPATH>", "wsl path"),
    (r"/private/var/containers/Data/Application/[0-9A-F-]{36}", "/private/var/containers/Data/Application/<UUID>", "app container"),
    (r"\b00008[0-9a-fA-F]{3}-[0-9a-fA-F]{16}\b", "<SERIAL>", "device serial"),
    (r"\b[0-9a-fA-F]{40}\b", "<HEX40>", "udid-like"),
    (r"\b[a-z0-9][a-z0-9-]*\.ts\.net\b", "<RELAY_HOST>", "relay host"),
    (r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b", "<CGNAT_IP>", "tailscale address"),
    (r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", "<BOT_TOKEN>", "bot token"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}", "<GH_TOKEN>", "github token"),
    (r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}", "<API_KEY>", "api key"),
]

HEXDUMP = re.compile(r"^\s*[0-9a-fA-F]{8}:")
BLOB = re.compile(r"(?:[0-9a-fA-F]{2}\s){24,}")


def sanitize_line(line: str) -> str:
    out = line
    for pattern, repl, _why in REDACT:
        out = re.sub(pattern, repl, out)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--keep-prefix", action="append", default=None)
    ap.add_argument("--keep-contains", action="append", default=None,
                    help="line is kept if it contains this token anywhere (e.g. VENDED)")
    args = ap.parse_args(argv[1:])

    prefixes = tuple(args.keep_prefix) if args.keep_prefix else DEFAULT_PREFIXES
    needles = tuple(args.keep_contains or ())

    with io.open(args.src, encoding="utf-8", errors="replace") as fh:
        raw = fh.read().replace("\\n", "\n")

    kept, dropped_blob, kept_other = [], 0, 0
    for line in raw.split("\n"):
        s = line.rstrip()
        if not s:
            continue
        if HEXDUMP.match(s) or BLOB.search(s):
            dropped_blob += 1
            continue
        if not (s.startswith(prefixes) or any(n in s for n in needles)):
            kept_other += 1
            continue
        kept.append(sanitize_line(s))

    with io.open(args.dst, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(kept) + "\n")

    print(f"{args.src} -> {args.dst}: kept {len(kept)}, dropped {kept_other} non-matching, "
          f"dropped {dropped_blob} hex/blob lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
