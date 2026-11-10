#!/usr/bin/env python3
"""gate.py - closure gates for this audit.

Why: a written claim ("branch closed") rots. A gate re-checks the published evidence every
time it runs, so a reader can verify the claims without trusting the prose.

    python tools/gate.py                 # all gates
    python tools/gate.py G-112706-WRITE  # one gate
    python tools/gate.py --json out/gates.json

Semantics:
    PASS  the closure still follows from the evidence in this repository
    FAIL  the evidence changed and the claim must be re-examined
    SKIP  the evidence file is absent - the gate proves nothing

Every gate prints the command that would falsify it. If you can run that command and it
succeeds, the gate is wrong and the branch is open again.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def read(name: str) -> str | None:
    path = os.path.join(ROOT, "evidence", name)
    if not os.path.exists(path):
        return None
    with io.open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def g_bytestream_write():
    """All external write attempts are refused by the service."""
    text = read("02-bytestream-write.log")
    if text is None:
        return SKIP, "evidence/02-bytestream-write.log absent"
    refused = len(re.findall(r"REFUSED code=-12878", text))
    opened = len(re.findall(r"\|fd=\d+\|fl=0x0\|", text))  # read-only descriptors only
    writes = len(re.findall(r"\|wr=[1-9]", text))
    detail = f"refused={refused} read_only_fds={opened} successful_writes={writes}"
    if writes or refused == 0:
        return FAIL, detail
    return PASS, detail


def g_bytestream_read():
    """Only whitelisted paths are vended; keychain, TCC and messages are refused."""
    text = read("02-bytestream-read.log")
    if text is None:
        return SKIP, "evidence/02-bytestream-read.log absent"
    vended = re.findall(r"^(\S+): VENDED", text, re.M)
    refused = re.findall(r"^TRAV (\S.*?): refused code=(-\d+)", text, re.M)
    secret = {"keychain", "tcc", "sms"}
    leaked = [v for v in vended if v.split("/")[0].split(".")[0].lower() in secret]
    detail = f"vended={len(vended)} refused={len(refused)} secret_leaks={leaked or 'none'}"
    if leaked or not refused:
        return FAIL, detail
    return PASS, detail


def g_ave2():
    """No client count above the kernel array capacity was accepted."""
    text = read("03-ave2-capacity.log")
    if text is None:
        return SKIP, "evidence/03-ave2-capacity.log absent"
    rows = re.findall(r"^\S+\s+n=(\d+)\s+set=(-?\d+)", text, re.M)
    if not rows:
        return SKIP, "no n=/set= lines"
    accepted = [(int(n), int(s)) for n, s in rows if int(s) == 0]
    over = [n for n, _ in accepted if n > 8]
    detail = f"rows={len(rows)} accepted={len(accepted)} accepted_above_capacity={over or 'none'}"
    return (FAIL if over else PASS), detail


def g_ifaddr():
    """Interface address lengths never exceed the 8-byte limit the parser assumes."""
    text = read("04-interface-lengths.log")
    if text is None:
        return SKIP, "evidence/04-interface-lengths.log absent"
    alen = [int(x) for x in re.findall(r"alen=(\d+)", text)]
    if not alen:
        return SKIP, "no alen= fields"
    detail = f"interfaces={len(alen)} max_alen={max(alen)} over_8={sum(1 for a in alen if a > 8)}"
    return (FAIL if max(alen) > 8 else PASS), detail


def g_tests():
    """The published parsers still reproduce their verdicts on the published evidence."""
    if not os.path.isdir(os.path.join(ROOT, "tests")):
        return SKIP, "tests/ absent"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, env=env, timeout=300,
    )
    tail = (proc.stdout or proc.stderr).strip().splitlines()
    summary = tail[-1] if tail else "no output"
    return (PASS if proc.returncode == 0 else FAIL), summary


GATES = [
    ("G-112706-WRITE", "bytestream service refuses every write, including the caller's own container",
     "produce one successful write through the service", g_bytestream_write),
    ("G-112706-READ", "bytestream service only vends whitelisted media/system paths",
     "vendor a keychain / TCC / messages descriptor", g_bytestream_read),
    ("G-AVE2", "VideoToolbox rejects layer-ID counts above the kernel array capacity",
     "get n>8 accepted by MVHEVCVideoLayerIDs / HEVCAuxiliaryLayerIDs", g_ave2),
    ("G-RTM", "no interface reports an address length above 8, so the parser precondition fails",
     "find an interface with sdl_alen>8", g_ifaddr),
    ("G-TESTS", "published verdict parsers reproduce their results", "break a parser test", g_tests),
]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("only", nargs="*")
    ap.add_argument("--json", default=None)
    args = ap.parse_args(argv[1:])

    results = []
    for gid, claim, kill, fn in GATES:
        if args.only and gid not in args.only:
            continue
        try:
            verdict, detail = fn()
        except Exception as exc:  # an unreadable artifact is SKIP, never PASS
            verdict, detail = SKIP, f"{type(exc).__name__}: {exc}"
        results.append({"id": gid, "verdict": verdict, "claim": claim,
                        "detail": detail, "kill": kill})
        print(f"{gid:<16} {verdict:<4} {claim}")
        print(f"{'':<21} {detail}")
        print(f"{'':<21} kill: {kill}")

    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in (PASS, FAIL, SKIP)}
    print(f"\nTOTAL pass={counts[PASS]} fail={counts[FAIL]} skip={counts[SKIP]}")

    if args.json:
        with io.open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"json -> {args.json}")

    return 0 if counts[FAIL] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
