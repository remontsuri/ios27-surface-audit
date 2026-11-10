# IOSurface notify race (CVE-2026-112477) — a use-after-free that is only a denial of service

**Status:** closed — reproducible kernel panic, no controlled dereference possible.
**Component:** `com.apple.iokit.IOSurface`, `s_set_surface_notify` (selector 17).

## Claim

The use-after-free is real and easily triggered from a sandboxed app. It cannot be turned into
a memory-corruption primitive, because the object field read at the dereference site is never
attacker-controlled — not "we failed to win the race", but "the input never reaches that
offset".

## The race

Selector 17 registers a notification callback: the driver allocates a listener node and links
it into a per-client list. Tearing the client down while the notification dispatcher is walking
that list frees the node mid-walk. With the surface reference count driven to zero, the
dispatcher reads a freed node.

Delivery to the dispatcher was verified from a normal app; the crash is stable and its signature
is identical across runs.

## Where the dispatcher actually reads

Disassembly of the dispatch loop:

```
ldr x22,[x20,#0x188]     ; head of the listener list
loop:
  ldr x0,[x22,#0x58]     ; argument passed to the callback
  bl  <callback>
  ldr x22,[x22]          ; next node
```

The constructor stores two things into the node:

* the first 16 bytes of the `structure input` buffer go to `node+0x10`;
* `node+0x58` receives `x3`, which is the `IOSurfaceClient` itself (`self`).

So the dereference consumes a *kernel-chosen* pointer, not the user buffer. The user buffer
lands at `+0x10`, which this path never reads.

## Panic evidence

One of the reproduced panics (iOS 27.0.1, build 24A446):

```
pc 0xfffffff03786e014   lr 0xfffffff037287760
x0 = 0   x1 = 0xffffffdd36b84380   x2 = 0   x3 = 0xc4
FAR = 0x8   ESR = 0x96000006
```

`x0` is the value loaded from `node+0x58` after the node was freed: it is zero, and the callback
faults reading `[0 + 0xd8]`. A marker placed in the user buffer (`0x41414141…`) never appears in
any register — the input does not survive to the fault point.

## Why same-type reclaim does not help

The allocation is a typed zone (`kalloc_type`, class 96, signature `111111111121`). Enumerating
that class shows exactly three zone kinds sharing the signature, and all three are the same
notify node; the only other near-signature structure belongs to a root-only subsystem. So the
freed slot can only be refilled by another notify node — which, by the same constructor, writes a
valid client pointer into `+0x58` again.

Result: after any reclaim the dispatcher dereferences *some* client, never a value of our
choosing. That is a denial of service by construction, and it matches the vendor wording
("unexpected system termination").

## What this changes elsewhere

* The "info leak through the notify fields `+0x28`/`+0x38`" hypothesis is void: those fields are
  not read by the dispatch path.
* The "re-register notify to gain control" idea is void for the same reason: it yields a pointer
  to another client.

## How to falsify this

Find, anywhere in the dispatch loop or the callback, a read of a field that the constructor
populates from the user buffer (`node+0x10` and onward). At the time of writing that search
returns zero hits.

## Artifacts

* dispatch loop and constructor addresses (build 24A446): `0xfffffff009bf9ac0`,
  `0xfffffff009bf98c0`; callback `0xfffffff009c03718`.
* selector table entry for 17: handler `0xfffffff009bfd0c4`.
