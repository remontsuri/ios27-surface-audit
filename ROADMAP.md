# Roadmap

Open branches only. Each one carries a stop condition and the experiment that would kill it —
if the kill condition is met, the branch is closed in writing and not retried.

Two of them are a few days of work; one is a half-day of static analysis.

---

## 1. Patch-diff 27.0.1 (24A446) against 27.2.1 (24B156)

**Why:** every previous differential was taken against 27.2 (24B119). 27.2.1 shipped later and
has never been compared. A security fix that appears between 24A446 and 24B156 points at a
defect that is still live on the audit build.

**What to look for:** not "what changed", but *fixed defects with a controllable shape* — a
missing bound check that was added, where the input is attacker-controlled. That is exactly
how three earlier branches (`rtm_scrub`, the AVE2 validator, `Compression`) were located.

**How:** extract both kernels, list `LC_FILESET_ENTRY` kexts, diff function bodies after
normalising relocations and addresses (addresses move between builds; code does not).

**Stop condition:** 5 working days.
**Kill:** if the diff yields only the already-known fixes (IOSurface notify race, AVE2
temporal layers, Compression), close the branch in writing.

---

## 2. Delivery oracle for the DV-RPU parser (CVE-2026-112688 path)

**Why:** the Dolby Vision RPU parser in CoreMedia has a measured out-of-bounds write into a
stack frame, with attacker-controlled index and value. What has never been shown is that a
file supplied by an application can actually reach that parser.

**Current evidence against it:** no direct callers of the RPU entry point inside CoreMedia
itself (536 154 instructions scanned), no matching strings in VideoToolbox, AVFoundation or
the media daemons, and the pointer-authentication epilogue turns the write into a crash rather
than a jump. That is why the goal is *delivery*, not code execution.

**How:** three runs, one per candidate entry, each answering a single binary question — does a
crash report appear, and in which process:
1. HLS with `SUPPLEMENTAL-CODECS="dvh1.08.xx/db1p"`;
2. a container carrying the Dolby configuration record but no RPU NAL unit;
3. `AVAssetImageGenerator` / Quick Look thumbnail path.

**Stop condition:** 3 days, 3 runs, zero kernel panics (a daemon crash is an acceptable result,
it produces a report without rebooting the device).
**Kill:** three negative answers close the branch permanently.

---

## 3. Daemon file-follow behaviour (static only)

**Why:** the sandbox escape in `docs/02` gives read access to a narrow file whitelist and
write access to an app-group container. The open question was whether a system daemon that
consumes a file from that container will follow a symlink placed there.

**Correction to earlier framing:** the interesting question is not "does the daemon follow
symlinks" but "can it — is `O_NOFOLLOW` used, what does its sandbox profile allow, and who
writes that file at all". Three of those are answered statically.

**How:** disassemble the `open`/`fopen` call sites of the relevant daemons, read the sandbox
profile, and check whether any code path writes the file under attacker control.

**Stop condition:** 4–6 hours.
**Kill:** if every call site uses `O_NOFOLLOW` or the file is written by a privileged process
only, close the branch without touching a device.

---

## Not on the roadmap

* **Fuzzing kernel user clients on this rig.** One probe run is a manual build, sign, install,
  launch-and-hold cycle. Kernel fuzzing needs thousands of runs; the pipeline is the
  bottleneck, not the idea.
* **"Audit all user clients" as a task.** The reachable set from a sandboxed app was measured
  and is essentially one client family; the rest answer `kIOReturnNotPrivileged` or do not
  expose a user client at all.
* **Using a virtualised iOS guest as a test bench.** The guest boots, but it has no IOKit
  service plane, so the probes that matter cannot run there. See `docs/07`.

---

## How a branch gets closed

A branch moves to "closed" only when all four are written down:

1. the claim (what cannot happen);
2. the measurement that supports it (command + output, or binary analysis with addresses);
3. the mechanism (why it cannot happen, not "we tried");
4. the kill command (what would prove the claim wrong).

`tools/gate.py` encodes those gates so a later reader can re-run them instead of trusting prose.
