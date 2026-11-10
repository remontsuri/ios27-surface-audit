# Panic attribution: why the count was wrong, and how to group reports

**Status:** correction. No new bug is claimed here — this document is about reading crash
reports correctly.
**Corpus:** the eight distinct `panic-full` reports still present on the analysis machine, read
directly from their JSON payloads, on iOS 27.0 / 24A437 and 27.0.1 / 24A446.

## Claim

"Nine IOSurface panics" is not a measurement. Of the eight panic reports that still exist, **one**
carries the IOSurface notify signature. Five are a write fault in the video encoder, one is the
encoder's neighbouring list initialiser, and one is not from this device at all.

The count grew for three separate reasons, each of which is cheap to avoid: two different bugs
were grouped because both showed "a bad pointer", a report from another device model was folded
in, and a *session* counter (how many times the phone rebooted while a probe was installed) was
reported as a *signature* count.

The original grouping was not the problem. A sweep of the device's reports on 30.10 did group
eight IOSurface reports into one key once the addresses were normalised — that measurement
stands. The damage happened afterwards, when later reports that merely arrived during a probe
session were added to the same column without re-reading their registers.

## The corpus

Eight distinct reports. Report names are Apple's timestamps; `pc` and `lr` are the values on the
panic header line (`... at pc X, lr Y (saved state: ...)`), not from a thread dump further down
the file — those differ, and picking the wrong one silently changes the answer.

| report | device | build | panicked task | pc | lr | x0 | ESR | FAR |
|---|---|---|---|---|---|---|---|---|
| 2026-10-28 01:41:35 | iPhone18,1 | 24A446 | videocodecd | `0xfffffe004345b188` | `0xfffffe00435710c4` | `0x100000059` | `0x96000046` | `0x100000059` |
| 2026-10-31 22:19:52 | iPhone14,7 | 24A437 | kernel_task | `0xfffffff04a2b7d70` | `0xfffffff04a3ce3ac` | `0x79` | `0x96000005` | `0x79` |
| 2026-10-31 22:33:41 | iPhone14,7 | 24A437 | videocodecd | `0xfffffff049f87d48` | `0xfffffff04a09dc84` | `0x59` | `0x96000046` | `0x59` |
| 2026-11-03 00:13:53 | iPhone14,7 | 24A446 | videocodecd | `0xfffffff034d13d48` | `0xfffffff034e29c84` | `0x59` | `0x96000046` | `0x59` |
| 2026-11-03 10:53:25 | iPhone14,7 | 24A446 | videocodecd | `0xfffffff02f39bd48` | `0xfffffff02f4b1c84` | `0x59` | `0x96000046` | `0x59` |
| 2026-11-03 11:09:40 | iPhone14,7 | 24A446 | videocodecd | `0xfffffff049793d48` | `0xfffffff0498a9c84` | `0x59` | `0x96000046` | `0x59` |
| 2026-11-03 13:59:16 | iPhone14,7 | 24A446 | backboardd | `0xfffffff03786e014` | `0xfffffff037287760` | `0` | `0x96000006` | `0x8` |
| 2026-11-05 17:17:04 | iPhone14,7 | 24A446 | videocodecd | `0xfffffff033a5fd48` | `0xfffffff033b75c84` | `0x59` | `0x96000046` | `0x59` |

Several reports exist as duplicate copies under different paths; they are one report each,
identical by content hash. Userland crash reports (`JetsamEvent-*`, app crashes) are in the same
directories and are **not** panics — they carry no `panicString` and must not enter a panic count.

Decoding the two ESR values that appear:

| ESR | EC | WnR | DFSC | meaning |
|---|---|---|---|---|
| `0x96000046` | `0x25` data abort, same EL | 1 | `0b000110` | **write**, translation fault level 2 |
| `0x96000005` / `0x96000006` | `0x25` | 0 | `0b000101` / `0b000110` | **read**, translation fault level 1 / 2 |

So the corpus splits on the fault direction before anything else is read.

## The four signatures

| sig | key `(pc & 0xfff, lr & 0xfff, WnR, fault address class)` | count | what it is |
|---|---|---|---|
| A | `(0x014, 0x760, read, 0x8)` | **1** | IOSurface notify dispatch, NULL object |
| B | `(0xd48, 0xc84, write, 0x59)` | **5** | AppleAVE2 list-head initialiser, `x19 + 0x58`, `x19 = 1` |
| C | `(0xd70, 0x3ac, read, 0x79)` | **1** | the same initialiser family at `+0x78`, but the fault is a read |
| D | `(0x188, 0x0c4, write, 0x100000059)` | **1** | same arithmetic as B, bit 32 set, **different device model** |

Grouping on the low 12 bits is what separates them; grouping on the full address does not,
because the slide changes per boot (see below). Grouping on "x0 looks wrong" merges A and B,
which is exactly the mistake that produced the inflated count.

### A — IOSurface notify path (1 report)

```
pc 0xfffffff03786e014  lr 0xfffffff037287760
x0 = 0   x1 = 0xffffffdd36b84380   x2 = 0   x3 = 0xc4
FAR = 0x8   ESR = 0x96000006        slide = 0x2d684000
```

Attribution, from the report's own slide:

* `pc - slide = 0xfffffff00a1ea014` — main kernel text. The instruction at that address is
  `ldr x8,[x8]` (a load through a pointer), followed by `ldr x10,[x0,#0x30]` and an `eor` of the
  two — an authenticated-pointer comparison. The fault address `0x8` does **not** match that
  instruction's own operand, and that is why the faulting opcode is not asserted here: panic PCs
  in this region drift by ±1 instruction, and a claim built on the wrong one would be a claim
  about a neighbouring instruction.
* `lr - slide = 0xfffffff009c03760` — inside IOSurface, in the callback that starts at
  `0xfffffff009c03718`, at `+0x48`. This is the return address of the function that faulted, and
  it lands in the documented dispatch callback. **That** is the attribution: not the address
  range, but the return address inside a named function.
* `x0 = 0`, `FAR = 0x8` — a read at `[0 + 8]`, i.e. a field of a NULL object.
* The panicked task is `backboardd`, **not** the probe. The probe was installed at the time, and
  the mechanism is the one described in [docs/01](01-iosurface-112477.md), but the faulting
  thread belonged to the window server. Any sentence of the form "our probe panicked the kernel
  here" is therefore an inference from timing and mechanism, not something the task name
  supports. Read the task field before writing that sentence.

### B — the encoder's list-head initialiser (5 reports)

```
pc 0xfffffff049793d48  lr 0xfffffff0498a9c84
x0 = 0x59  x19 = 1  x1 = 6  x3 = 0xc0
FAR = 0x59  ESR = 0x96000046 (write)   task = videocodecd
```

The five reports span two builds and three boots, and collapse to one site:

* `pc - slide = 0xfffffff0083abd48`, which is `AppleAVE2.__TEXT_EXEC + 0xda78`
  (`0xfffffff0083abd48 - 0xfffffff00839e2d0 = 0xda78`).
* Read from the kext image, the four instructions are
  `a9000000 f9000800 b900181f d65f03c0` = `stp x0,x0,[x0]` · `str x0,[x0,#0x10]` ·
  `str wzr,[x0,#0x18]` · `ret`. That is a doubly-linked-list head being initialised with
  `next = prev = self` and a zero counter — through `x0`.
* `x0` is not a stale pointer with a plausible value; it is `x19 + 0x58` with `x19 = 1`, i.e.
  exactly `0x59`. The value written is the pointer itself and zero, so there is no payload. A
  fixed, non-steerable address: denial of service, not a primitive.
* The caller sits in the encoder's DPB path; a separate static reading found `AVE_DLList.c` and
  its assert line numbers next to the calling code. That is corroboration, not the proof — the
  proof is the four instructions above.

**One number in an earlier note is wrong and is corrected here.** That note wrote
`__TEXT_EXEC+0x9a78`. The measured offset is `+0xda78`; the same note separately says the
neighbouring site is `+0x28` further, and the neighbour measures `+0xdaa0`. Two independent
sources in the working notes (`FINDINGS_ave2_cve_2026_112705`, `FINDINGS_ave2_ane_hunt`) also
say `+0xda78`. Use `0xda78`.

### C — the neighbouring site, read instead of write (1 report)

`pc 0xfffffff04a2b7d70 - slide = 0xfffffff0083abd70` = `+0xdaa0` in the same kext, and the
instruction there is `f9400008` = `ldr x8,[x0]`. `x0 = 0x79 = 1 + 0x78`, so this is the second
list initialiser the same caller runs (`add x0,x19,#0x78`), reached with the same garbage
`x19 = 1`. Kept separate from B because the site, the fault direction and the panicked task
(`kernel_task`) all differ; merging them would hide that the caller is off by a fixed 0x20
between two initialisers.

### D — not this device (1 report)

`product = iPhone18,1`. It reproduces the family arithmetic (`x0 = 0x100000059`, the same
`1 + 0x58` with bit 32 set) on another SoC, which is mildly interesting and is the only thing it
can be used for. It cannot be counted as a panic of the audit device, and it should not sit in a
table that answers "how many times did this build crash".

## How the reports were grouped

1. **Normalise the PC through the image that owns it, then group on the low 12 bits.** Not on the
   full address: the same function appears as `0xfffffff02f39bd48` and `0xfffffff049793d48` in
   two reports, and as `0xfffffff031572014` and `0xfffffff04f19e014` in two others. Full-address
   grouping counted eight reports as eight causes; normalised grouping counted them as one.
2. **Take the signature tuple**: `(pc & 0xfff, lr & 0xfff, WnR, fault-address class)`. The link
   register is part of the key on purpose — signature A and signature B differ in both halves,
   and two bugs in the same function would share `pc` but rarely `lr`.
3. **Establish boot boundaries from `uptime` + `bootSessionUUID`, never from the device id.**
   Worked example: a capture at 12:32:10 reported `uptime = 4900 s` → boot at 11:10:30, which is
   the 11:09:40 panic plus 50 s. Between 11:10:30 and 12:32:10 there was no reboot, so a
   `NoDeviceConnectedError` window at 11:39–11:40 and a change of the device id from 16 to 17
   were USB multiplexer glitches, not panics. Counting them as reboots would have added two
   phantom events to the session.
4. **Exclude non-panic reports by file content, not by directory.** `.ips` files in the crash
   directory includes app crashes and jetsam events.

## The address rule, and the trap inside it

The rule that works: **`pc - slide` gives a static address; resolve that static address through
the image that owns it; identify the function by its return address, not by a range guess.**

The trap: a single global shift applied to the whole kernelcache lands on plausible but
unrelated code. Measured on this corpus: shifting `0xfffffff0083abd48` by the kernel text offset
and reading the kernel file yields `bti c; b; bti c; pacibsp` — perfectly valid instructions, at
the right address by arithmetic, and nothing to do with the fault. Mapping the same address
through the encoder kext's own `__TEXT_EXEC` yields the four instructions that *explain* `FAR`.
An address that decodes to real code is not evidence that you decoded the right code.

## What the correction changes

* **The count.** Reports with the IOSurface signature in the surviving corpus: **1**. The
  encoder family: **6** (five B, one C), of which one is from another device model. So the number
  that can be defended is "one surviving report per signature A", not "nine IOSurface panics" —
  the nine mixed signatures, sessions and one foreign device, and nothing in the corpus
  reproduces it.
* **"Reproduced 9 times" is unverifiable from what survives.** The working notes claim eight
  reproductions from the race probe, plus one from a later probe. Those reports are no longer on
  the device or in this corpus; what survives from 27.10 are three synthetic fixtures of 446–1067
  bytes. The claim may well be true, but the artefacts behind it are gone, so it cannot be cited
  as evidence. The experiment that would restore it: re-run the race probe, pull the reports,
  and count them **by signature**.
* **Which branch each report belongs to.** [docs/01](01-iosurface-112477.md) is the IOSurface
  DoS; the encoder write is a separate closed branch and must not be used as corroboration for
  the IOSurface race, or vice versa. Two bugs close to each other in time are still two bugs.
* **Per-report claims need the task field.** A panic in `backboardd` is not a statement about a
  probe's own process.

## Falsifiers

* A report with `FAR = 0x8`, `x0 = 0` and a panicked task of `videocodecd` — the A/B split is
  then wrong.
* A report with `FAR = 0x59` whose `lr - slide` lands inside IOSurface — the split is then wrong
  in the other direction.
* A boot whose `uptime` contradicts the timestamp differences between two reports — the boot
  grouping is then wrong, and any "N reboots" statement collapses.
* Re-running the race probe and pulling more than one report with signature A — which would
  raise the supported count, and is the measurement this document is missing.
