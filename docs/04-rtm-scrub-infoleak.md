# `rtm_scrub` / `dlil_ifaddr_bytes` — an info leak whose precondition never holds

**Status:** closed — the caller-side requirement is not satisfiable on this device.
**Component:** kernel routing / interface address handling.

## Claim

A publicly described out-of-bounds read in the routing scrub path requires an interface whose
link-layer address length (`sdl_alen`) exceeds 8 bytes. On the audited device no interface
reports more than 6, so the parser never takes the oversized path.

## The defect, briefly

The helper that copies a link-layer address trusts `sdl_alen` when sizing the copy, while the
destination buffer is fixed at 8 bytes. In 27.2 the code became `min(alen, 8)` plus zero-fill,
which is the signature of a hardening change rather than a redesign — that difference is what
made the branch worth measuring at all.

## The measurement

A probe enumerates every interface and prints the lengths as the kernel reports them:

```
IFC name=lo0     type=24  nlen=3 alen=0 slen=0 len=20
IFC name=XHC0    type=1   nlen=4 alen=0 slen=0 len=20
IFC name=pdp_ip0 type=255 nlen=7 alen=0 slen=0 len=20
...
```

Aggregate over 31 interfaces: `max_alen = 6`, count of `alen > 8` is zero.

The full measurement is in [`evidence/04-interface-lengths.log`](../evidence/04-interface-lengths.log)
and is re-checked by gate `G-RTM`.

## Why this closes the branch

The oversized read needs `alen > 8` at the moment the scrub runs. Interface address lengths come
from the drivers and the network stack, not from a value an app can set; the enumeration above
covers the interfaces that exist on this hardware. Without a path that produces a longer address,
the vulnerable copy never happens.

This is not "the bug is fixed" — it is "the bug is unreachable from this device's interface set".

## How to falsify this

Show an interface on this device with `sdl_alen > 8`, or another caller of the same helper that
takes the length from a different, attacker-influenced source.

## Note on transferability

The same comparison against 27.2.1 is still open (`ROADMAP.md`, branch 1): if a driver in a later
build gains an interface type with a longer address, the precondition could become satisfiable.
