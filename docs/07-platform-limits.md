# Bench options that did not work: virtual guest, Cinder27, SPTM/DART

**Status:** all three closed as entry points. Recorded so they are not re-run.

A short note on each: what it was hoped to give, what was measured, and the mechanism that ruled
it out.

## 1. A virtualised iOS guest as a test bench

**Hope:** run the same probes on a local virtual device instead of the physical phone.

**Measured:** the guest boots to a shell, but it has no IOKit service plane — opening the
`IOSurfaceRoot` service and similar returns `kr=1102` (unsupported). The shared-library cache is
several gigabytes and does not fit in the ramdisk the boot chain accepts (it is capped near 4 GiB),
and ad-hoc signed libraries are rejected by the code-signing enforcement layer, so the frameworks a
probe needs cannot be staged. A process that allocates a Mach port or writes to a read-only page is
killed (`SIGBUS` / `Killed: 9`).

**Mechanism:** the guest keeps the BSD system-call surface but not the driver/service plane that
the interesting bugs live in. Conclusion: good for syscall-level experiments, useless for IOKit.

## 2. Cinder27 as a source of a write primitive

**Hope:** a publicly circulated capture/analysis tool carried a usable primitive for this build.

**Measured:** 62 journal entries, of which one is a read-only descriptor leak, nine are crashes,
two are parser errors and 48 carry no data. Nothing in the set produces a controlled write.

**Mechanism:** the interesting log entries describe the *absence* of a capability, not its
presence. Closed as a source; kept in the record because "the tool ran without errors" is often
mistaken for "the tool found something".

## 3. SPTM / DART (`GAPF`) as an entry point

**Hope:** the firmware/DART path that the vendor hardened in a later release could be reachable
from an app, giving a path into the protected memory system.

**Measured:** in the DART driver on this build there is no user client at all — zero user-client
classes, zero `externalMethod` handlers. The GAPF feature is switched by boolean keys read from
the device tree; those keys are absent from the on-disk tree, and the runtime tree is not readable
without kernel access. The syslog oracle that would announce the feature is a warning emitted only
on an anomaly, and it never appeared across runs that exercised the encoder and camera.

**Mechanism:** no selector to call, and the feature is off by configuration. A path that requires
either kernel read (to see the runtime tree) or a supervisor-only key is not an *entry point* — it
is a target that presupposes the primitive being sought.

## What this section is for

Each of these cost real time. The value of writing them down is that the next attempt starts from
"measured, mechanism, falsifier" instead of from "let us try the VM again".
