# CoreMedia bytestream sandbox escape (CVE-2026-112706) — what it actually grants

**Status:** confirmed on-device; **read-only**, narrow whitelist; write path closed.
**Component:** CoreMedia "bytestream" service used by media clients.

## Claim

A sandboxed app can obtain read-only file descriptors from a media system service. The
descriptors are stable, the content is real, and several of them belong to files the app cannot
open itself. But the set is a whitelist — two directories — and the same service refuses every
write attempt, including writes into the app's own container.

## Read side

The probe asks the service to vend a descriptor for a list of targets, and records both what the
service returned and whether the app could open the same path directly.

```
MediaLibrary.sqlitedb: VENDED fd=3 size=24592 direct_open_errno=1
PlayCounts.plist:      VENDED fd=3 size=8     direct_open_errno=1
iTunes_dir:            VENDED fd=3 size=0     dir=1 direct_open_errno=1
TRAV keychain:  refused code=-12203
TRAV TCC:       refused code=-12203
TRAV sms:       refused code=-12203
TRAV Library:   refused code=-12203
```

Aggregate metric over the run: `vended=5 denied=10 bytes_read=24656 result=ESCAPE`.
Two of the five "vended" entries (`SystemVersion.plist`, `.GlobalPreferences.plist`) are files the
app can read directly, so they are not an escape; three are genuine.

Everything outside `Media/iTunes_Control` and `/System` answers `-12203` (sandbox deny). The
app-container path answers `-17913` (no such file — the service cannot see it).

## Write side

Three probe rounds, with the third fixing a control bug (the earlier rounds created the target
file via their own `open()` with `O_CREAT`, which produced a misleading `EEXIST`).

Clean round:

* create a fresh file in the app's own `Documents` with `O_WRONLY|O_CREAT` → `-12878` (server
  refuses the write);
* read-only open of an existing container file → `-12203` (server does not see the container);
* read-only open of a media database → `fd=3, size=24592` (read works).

So the service cannot be used to write, not even inside the caller's own sandbox, and it has no
view of app containers.

## Independence from entitlements

The same binary re-signed with only `get-task-allow` (no `platform-application`, no
`task_for_pid-allow`, no `run-unsigned-code`) produced the same metric and the same file lists.
The behaviour is a property of the service, not of the client's entitlements.

## Why this is not a jailbreak step by itself

It is stage one of a chain: file read outside the sandbox, no write, no code execution in a
privileged process. Any chain that starts here needs a second stage inside the media daemons.

## How to falsify this

* Produce a `VENDED` descriptor for a keychain, TCC or messages database, or for any path outside
  `Media/iTunes_Control` and `/System`.
* Produce any successful write through the service, anywhere.

## Artifacts

Server-side logic lives in the MediaToolbox framework, not in the playback daemon (the daemon is
absent from the shared cache). The 27.2 hardening described by the vendor is a path whitelist plus
descriptor-type validation in the daemon; the framework side is logically unchanged between the
audited build and 27.2.
