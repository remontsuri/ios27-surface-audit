# iOS 27 attack-surface audit — notes and negative results

Research notes from auditing the kernel and userland attack surface of **iOS 27.0.1
(build 24A446)** on a personally owned **iPhone 14 (A15 / t8110)**.

The goal was narrow: find a memory-corruption primitive in a component reachable from a
sandboxed application, strong enough to reach kernel memory. This repository records what
was measured, what was ruled out, and why — including the failures, because a documented
negative result is what stops the next person from repeating the same month of work.

> Scope: one owned device, no third-party targets, no service disruption. Everything here
> is either static analysis of shipped binaries or a signed probe app running on that device.

## What this repository is

* **A falsification record.** Every closed branch states its claim, the measurement behind
  it, and the single experiment that would prove the claim wrong.
* **A method**, not a toolkit: how to go from "component looks interesting" to "reachable,
  controllable, or provably not" without fooling yourself.
* **A roadmap** for the branches that are still open (`ROADMAP.md`).

It is **not** an exploit, a jailbreak, or a set of weaponised primitives. Nothing here
achieves kernel read/write.

## Status of the branches

| Branch | Outcome | Detail |
|---|---|---|
| IOSurface notify race (CVE-2026-112477) | **DoS only** | [docs/01](docs/01-iosurface-112477.md) |
| CoreMedia bytestream sandbox escape (CVE-2026-112706) | read-only whitelist | [docs/02](docs/02-bytestream-112706.md) |
| AppleAVE2 temporal-layer / auxiliary-layer IDs | rejected before the kernel | [docs/03](docs/03-ave2-temporal-layers.md) |
| `rtm_scrub` / `dlil_ifaddr_bytes` info leak | unreachable (precondition fails) | [docs/04](docs/04-rtm-scrub-infoleak.md) |
| CoreGraphics type-5 shading (CVE-2026-112611) | address shaped by a double from the file, value fixed, not steerable | [docs/05](docs/05-pdf-cg5-write.md) · [docs/08](docs/08-pdf-shading-sites.md) · [docs/09](docs/09-cg-shading-r136-fixture.md) |
| ImageIO planar TIFF decode | check absent on 24A446, no file-driven trigger found | [docs/10](docs/10-imageio-tiff-planar.md) |
| MobileGestalt cache, `bad_query` class 13 | userland / out of window | [docs/06](docs/06-mobilegestalt-and-userland-paths.md) |
| QEMU guest, Cinder27, SPTM DART | not viable as entry points | [docs/07](docs/07-platform-limits.md) |

Open branches and their stop conditions are in [`ROADMAP.md`](ROADMAP.md).

Every CVE this audit touched — including the ones that turned out useless — is listed in
[`CVES.md`](CVES.md) with the status of *our* measurement and the falsifier that would change it.

## Method

1. **Start from reachability, not from a bug.** A defect that cannot be reached from a
   sandboxed process is a defect with no value for this goal. Every branch below was first
   checked for an entry point that a normal app can open.
2. **Two independent readings of the same code.** Disassembly (capstone / Ghidra) is checked
   against decompiler output, and both against observed behaviour on the device. When the
   three disagree, the branch is not closed — it is "unknown".
3. **Registers over stories.** A crash report gives `pc`, `lr`, `x0…x3`, `FAR`, `ESR`. Those
   five numbers decide whether the fault is at the site you think it is. Several early
   conclusions in this project were wrong until the panic registers were read carefully.
4. **A closure needs a kill command.** "Closed" is only recorded next to the command that
   would reopen it. If nobody can state that command, the branch is not closed.
5. **Same-type reclaim is a precondition, not a detail.** For a use-after-free to become a
   primitive, the freed slot must be refillable by an object whose fields you control. Where
   that is impossible by construction, no amount of race tuning helps.

## Reproducibility notes

The measurements were taken with locally held firmware artifacts (kernelcache, kexts,
framework binaries extracted from the shipping OS). Those artifacts are **not** distributed
here; obtain them from your own device or your own IPSW. `tools/gate.py` documents the gate
mechanism used to keep closures honest — it reports `SKIP` when the local artifact is absent,
which is the correct answer for a reader without the same binaries.

What can be run directly from this repository:

```sh
python tools/gate.py        # re-checks the closures against the published evidence
python -m pytest            # 42 tests over the verdict parsers
python tools/publish_scan.py --all   # the pre-publication scanner used on this tree
```

Probe apps used on the device were signed with a personal development certificate and
installed over a USB multiplexer relay; that infrastructure is intentionally not included.

## Layout

```
README.md      this file
CVES.md        register: every CVE touched, with our measurement status and falsifier
ROADMAP.md     open branches, stop conditions, kill criteria
cves/          one file per CVE we measured: what we saw, why the status is what it is
docs/          one file per branch: claim, method, evidence, falsification
evidence/      sanitized measurement logs the claims rest on
probes/        on-device probe sources that produced the evidence
tools/         gate.py (closure gate), sanitize_evidence.py, publish_scan.py, verdict parsers
tests/         tests for the verdict parsers
```

## A note on what "closed" means here

Closed does not mean "Apple fixed it", and it does not mean "nobody can exploit it". It
means: **given the entry points available to a sandboxed application on this build, this
branch cannot produce controlled memory corruption**, and the reason is a mechanism, not a
failed attempt. Each document says which mechanism, so the claim can be attacked directly.
