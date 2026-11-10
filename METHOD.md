# Method

This document describes the method behind the audit published in this repository, for a
reader who wants to apply it to a different component, a different build, or a different
platform. It is about how conclusions are produced and defended, not about the findings
themselves.

If you only read one section, read [6](#6-a-closure-ships-with-the-command-that-would-reopen-it).

---

## 1. The unit of work is a branch, not a bug

Work is organised as **branches**. A branch is one component, one suspected defect, one
question: *given the entry points a sandboxed application has on this build, can this
defect produce controlled memory corruption?* Everything else - the CVE identity, the
public write-up, the crash count - is metadata attached to that question.

A branch moves through three states, and each transition has a required artifact.

| State | Entered when | Required artifact |
|---|---|---|
| **open** | a public claim, a patch hint, or a suspicious shape in shipped code | the entry point to be tested, and a stop condition |
| **measuring** | the entry point is reachable from an unprivileged process | logs in `evidence/`, one command per measurement |
| **closed** | the mechanism is named, or the entry point is shown absent | the claim, the mechanism, and the kill command |

Open branches live in [`ROADMAP.md`](ROADMAP.md), each with a stop condition and a kill
criterion. Closed branches live in `docs/`, one file per branch.

### 1.1 Opening: reachability before the bug

Every branch starts by asking whether a normal application can reach the component at all.
A defect with no reachable entry point is a defect with no value for this goal, regardless
of how serious its description sounds.

This ordering is not bookkeeping. It removes branches cheaply and early. `docs/07` records
platform-level exclusions of exactly this kind, and `docs/06` records a userland cache that
is unreachable from the sandbox on this build. In both cases the conclusion was that the
entry point does not exist, and no exploit work was done.

The output of this step is a single sentence that names the entry point, for example:
*selector 17 of the IOSurface user client, callable from a sandboxed app with no
entitlement* - the starting point of [`docs/01`](docs/01-iosurface-112477.md).

### 1.2 Measuring: one command per number

A measurement produces a number, and the number has a command behind it. Not "the race
triggers", but: this probe, run this many times, produced this many panics with this
signature. The logs under `evidence/` are what the gate later re-reads, so a number that
exists only in prose is not a measurement.

Measurements must be taken through the **real entry point**. A parser can be called directly
from a test harness, and that is useful for establishing the arithmetic of the bug, but it
does not establish reachability. `cves/112688.md` keeps those two facts apart on purpose:
the write is real and measured, and the delivery path is not.

### 1.3 Closing: name the mechanism

A branch closes when a **mechanism** is named, not when attempts stop working. The
distinction is the whole point of the exercise:

* *"we could not win the race"* is a statement about the operator's patience;
* *"the field read at the dereference site is written by the kernel from `self`, and the
  attacker buffer lands at an offset this path never reads"* is a statement about the code,
  and it can be attacked directly.

The second form is what appears in `docs/01`, and it is the reason that branch is closed
rather than abandoned.

---

## 2. Evidence versus inference

The repository keeps three kinds of evidence and treats them differently.

**Evidence** - what the machine reported:

* **registers** from a crash report: `pc`, `lr`, `x0`-`x3`, `FAR`, `ESR`;
* **addresses** read from the shipping binary, with the build identified;
* **object state** - which field held which value, read from the live object or from
  instructions that provably write it;
* **counts** - how many of how many, for example "the formula holds in 20 of 20 reports"
  in [`docs/08`](docs/08-pdf-shading-sites.md).

**Inference** - what follows from a model of the code: a decompiler's reading of a function,
the expected effect of a constructor, the reason a check should reject an input.

**Inference of either kind is not evidence until it is checked against something that is
not the thing being checked.**

Practical consequences that were learned the hard way in this project:

* A **marker value is a control, not a decoration.** In `docs/01` a distinct pattern was
  placed in the user buffer and searched for in the registers at the fault. It never
  appeared. That absence is the single most informative result in the branch: it says the
  input does not reach the fault point, which is a mechanism, not a failed attempt.
* **A formula that holds in a subset is a red flag, not a result.** In `docs/08` the write
  formula matched 20 of 20 write-site reports and 0 of 43 read-site reports. Treating the
  two sites as one phenomenon would have produced a wrong story about both.
* **Offset arithmetic between builds is not transferable.** Two devices with the same SoC
  can ship different kernelcaches with a different address layout. Any address quoted here
  is tied to the build it was read from; re-derive it, do not translate it.
* **A decompiler disagreement is an open question.** When disassembly and decompiler output
  disagree about a store width or a branch condition, the branch is "unknown" until the
  instruction bytes decide it.

---

## 3. Why an independent oracle matters

The failure mode this rule prevents is circular: taking the expected value from the output
of the code under test. If the model and the code are the same source, a test that passes
proves that the code is consistent with itself.

Three independent readings are used, and they are compared rather than merged:

1. **Disassembly** of the shipping bytes (capstone, Ghidra), read at instruction level.
2. **A second reading** of the same code - decompiler output, or a hand re-derivation of the
   arithmetic from the instruction semantics.
3. **Observed behaviour** on the device, with registers.

`docs/08` adds a fourth, stronger step and names it explicitly: an **emulator executes the
real bytes of the shipping binary** at the fault sites, seeded with the register values
from the crash reports. If the model of the code is wrong, the emulated `FAR` disagrees with
the device. The device is the oracle; the emulator is a model that can be falsified against
it.

The same rule applies to the tooling in this repository. `tools/gate.py` re-reads the
published evidence instead of trusting the prose, and the tests pin literal expected values
rather than re-deriving them from the code they test. A test whose expectation is
`assert result is None` proves almost nothing; a test that asserts a specific rule name, line
number and exit code fails when the behaviour changes.

---

## 4. "Closed" is not "unexploitable"

These are different claims and the repository never upgrades one into the other.

* **Closed** means: given the entry points available to a sandboxed application on this
  build, this branch cannot produce controlled memory corruption, *and the reason is a
  mechanism*.
* **Unexploitable** is a claim about the world: nobody, with any access, will ever turn this
  into a primitive. This repository does not make that claim.

Three concrete examples of the difference, all from closed branches:

* [`docs/01`](docs/01-iosurface-112477.md) - the free is real and the crash is stable, but
  the freed allocation is a typed zone whose sharing signature is held by exactly three
  kinds, all of them the same notify node; any reclaim therefore writes a valid client
  pointer back into the field the dispatcher reads. The closure is about *this object
  layout on this build*.
* [`docs/08`](docs/08-pdf-shading-sites.md) - the write site stores a constant zero, and the
  address is shaped by a value that the file does not steer. Address control without value
  control is not a primitive, but it is not "safe code" either.
* `docs/02` - the bytestream escape is real and reproducible, and it is bounded to a
  whitelist of read-only paths. A reader who takes "sandbox escape" from the CVE title will
  overestimate it; the document states what was actually reached.

A closure is therefore always scoped: **to a build, an entry point set, and an object
model.** Change any of the three and the branch is open again, which is exactly what the
kill command in the next but one section is for.

---

## 5. The CVE status vocabulary

A CVE is a description of a defect, not a statement about what an attacker on this build can
do with it. The register in [`CVES.md`](CVES.md) therefore records *our* measurement, using a
fixed vocabulary. The words are load-bearing; do not substitute synonyms.

| Status | Meaning |
|---|---|
| **reproduced - DoS** | triggered on the device; the effect is termination, with no controlled memory access |
| **reproduced - partial** | one half of a primitive reproduced - for example address control without value control, or a write without a delivery path |
| **measured - denied** | the described capability does not appear on this build |
| **measured - unreachable** | the defect is present, but no entry point is reachable from a sandboxed app |
| **documented only** | read from public material; not measured here |
| **not tested** | known, out of scope or out of the version window |

Two rules keep this honest:

1. **No status better than "documented only" without steps 2 and 3.** A reachability check
   and a measurement, static or on device, are the price of any stronger word. A public
   write-up, however detailed, does not buy one.
2. **The falsifier is part of the entry.** A row without a statement of what would change it
   is incomplete, and the register says so.

`cves/112688.md` is the clearest example of the vocabulary doing work: the status is
**reproduced - partial**, and the file explains in the same breath that the parser bug is
certain and the delivery path is unproven. Neither half is allowed to imply the other.

---

## 6. A closure ships with the command that would reopen it

This is the rule that makes the rest checkable by a stranger.

> A closed branch is recorded next to the single experiment that would prove the closure
> wrong. If nobody can state that command, the branch is not closed.

Two mechanisms enforce it.

**In prose.** Every document in `docs/` ends with a falsification section. `docs/01` says:
find, anywhere in the dispatch loop or the callback, a read of a field the constructor
populates from the user buffer; at the time of writing the search returns zero hits.
`cves/112688.md` says: produce a crash report whose process is a media daemon, caused by a
file played through a normal API, and the delivery question reopens with a concrete target.

**In code.** [`tools/gate.py`](tools/gate.py) holds the same statements as executable gates.
Each gate has an id, a claim, a kill command, and a function that re-reads the published
evidence and returns one of three verdicts:

| Verdict | Meaning |
|---|---|
| `PASS` | the closure still follows from the evidence in this repository |
| `FAIL` | the evidence changed and the claim must be re-examined |
| `SKIP` | the evidence file is absent, so the gate proves nothing |

`SKIP` is not a pass. It is the correct answer for a reader who does not hold the same
binaries, and it is deliberately not counted as evidence in either direction.

The gate set is small on purpose - one gate per closure that rests on a log file, plus one
gate that re-runs the test suite:

```
python tools/gate.py          # all gates; exit 0 only when nothing FAILs
python tools/gate.py --json out/gates.json
```

A gate is written so that it fails on a *mechanism* change, not on a cosmetic one: it counts
`REFUSED code=-12878` lines and asserts that no successful write appears, rather than
matching a whole log file byte for byte.

---

## 7. Reproducing the claims in this repository

Two commands, run from a clean checkout with Python 3.11 and `git` available. Nothing else is
required: no firmware, no device, no network.

```sh
python tools/gate.py     # closure gates: expect TOTAL fail=0
python -m pytest         # published tests: expect all passed
```

The first re-checks the closures against `evidence/`. The second re-checks the verdict parsers,
so a parser that silently changes its mind is caught.

There is no CI service in this project: anyone with Python 3.11 and `pytest` reproduces every
check locally, which is also why the repository does not depend on a hosted runner being
available or free of charge.

Publishing hygiene is a separate concern and deliberately **not** part of this repository.
The maintainer runs a private scanner against the working tree before pushing; its rules encode
local identity strings and therefore cannot be published without defeating their own purpose.
Contributors get the standard upstream checks through `.pre-commit-config.yaml`.

---

## 8. Reusing this on another target

The checklist that the branches in this repository actually followed:

1. **Pin the build.** Write down the OS version and build, the device or machine, and the
   digest of every binary you analyse. Addresses without a build are not evidence.
2. **Choose the question.** Reachability and control, not "is there a bug". A defect that
   only terminates a process is a denial of service and should be recorded as one.
3. **Find the entry point first,** and prove it from an unprivileged process. If it is
   absent, close the branch in writing and stop.
4. **Read the code twice, independently,** and compare the readings at instruction level.
5. **Measure through the real entry point,** with registers or object state, and put the log
   in `evidence/`.
6. **Name the mechanism** that prevents control, if there is one. If there is none, the
   branch is open, not closed.
7. **Write the kill command** - the experiment that would prove you wrong.
8. **Encode the claim as a gate** in `tools/gate.py`, with `PASS`/`FAIL`/`SKIP` semantics,
   so the claim is re-checked instead of re-read.
9. **Run the leak scan** before publishing anything.

Steps 6 through 8 are the ones that survive contact with a reader. A negative result that is
scoped, mechanised and falsifiable is worth more than a positive result that nobody can
re-run.
