# The IOSurface method-dispatch table, and the rule it enforces twice

**Status:** artifact — the ABI map for `IOSurfaceRootUserClient`. It is what turned
[docs/01](01-iosurface-112477.md) from "the selector rejects everything" into a readable
interface.
**Component:** `com.apple.iokit.IOSurface`, `IOSurfaceRootUserClient`.
**Build measured:** iOS 27.0.1 (24A446) on iPhone 14 (A15); the second reading below is from
the 27.2 beta 4 kernelcache.

## Claim

An IOKit external method is reachable only when the caller matches the table entry exactly —
scalar counts *and* structure sizes, in **both** directions — and the dispatcher refuses before
the handler body runs. Reading the table converts "this selector returns
`kIOReturnBadArgument`" from a fuzzing problem into a lookup.

The practical consequence was large. For weeks every selector in this subsystem looked broken,
including `release_surface`, which was documented in public work and could not plausibly be
gone. The cause was not the selectors: the probe always passed a 512-byte output buffer and a
scalar output count, and any entry whose table row declares a zero output size refuses that
call before the handler is entered.

## Layout

One record is 40 bytes, stride `0x28`:

| offset | field | note |
|---|---|---|
| `+0x00` | `IOExternalMethodAction function` | arm64e chained fixup; the raw slot is an encoding, not a VA |
| `+0x08` | `checkScalarInputCount` u32 | |
| `+0x0c` | `checkStructureInputSize` u32 | `0xFFFFFFFF` = `kIOUCVariableStructureSize` |
| `+0x10` | `checkScalarOutputCount` u32 | |
| `+0x14` | `checkStructureOutputSize` u32 | |
| `+0x18` | `allowAsync` u8 | + 7 bytes of alignment |
| `+0x20` | `checkEntitlement` ptr | NULL in all 43 entries |

Two corrections to the first write-up of this table, both from measurement:

* **The stride is a 40-byte record, not "24 bytes of record plus 16 of padding".** The stride is
  the same number either way, but the padding explanation hides two real fields. `+0x18` reads
  as 0/1 and is 1 for exactly two entries, 17 and 40 — the two selectors that take an
  `asyncReference`. `+0x20` is NULL for all 43, which is the evidence that this subsystem
  declares **no** per-selector entitlement in the table.
* **The table has 43 entries, 0…42.** The first list stopped at 41; selector 42 exists
  (`scalars_in=4`) and was found by the kernelcache-level scan.

Table base, per build (kernelcache-level scan; the standalone extracted kext image uses
`0xfffffff00805b530`):

| build | table VA |
|---|---|
| 24A437 | `0xfffffff00805b530` |
| 24A446 | `0xfffffff0080648c0` |
| 27.2 beta 4 | `0xfffffff00806cc30` |

The three builds share the ABI: all 43 rows of `(scalars_in, struct_in, scalars_out,
struct_out)` are identical across 24A437, 24A446 and 27.2b4 — 0 differences, compared row by
row. Only the action pointers move.

## The table

`VARIABLE` = `0xFFFFFFFF` = `kIOUCVariableStructureSize` (no size check at the dispatch layer).
`0` means the direction is absent. The parser prints raw values, so its output shows
`0xffffffff` where this table says `VARIABLE`.

| sel | sc_in | st_in | sc_out | st_out |
|---|---|---|---|---|
| 0 | 1 | VARIABLE | 0 | 0xc68 |
| 1 | 1 | 0 | 0 | 0 |
| 2 | 0 | 0xc | 0 | 0xc68 |
| 3 | 0 | 0xc | 0 | 0x4 |
| 4 | 1 | 0 | 0 | 0xc68 |
| 5 | 2 | 0 | 0 | 0 |
| 6 | 0 | 0x20 | 0 | 0xc68 |
| 7 | 2 | 0 | 0 | 0xc68 |
| 8 | 1 | 0 | 1 | 0 |
| 9 | 0 | VARIABLE | 0 | 0x4 |
| 10 | 0 | VARIABLE | 0 | VARIABLE |
| 11 | 0 | VARIABLE | 0 | 0x4 |
| 12 | 3 | 0 | 0 | 0 |
| 13 | 0 | 0 | 0 | 0x28 |
| 14 | 2 | 0 | 0 | 0 |
| 15 | 2 | 0 | 0 | 0 |
| 16 | 1 | 0 | 1 | 0 |
| 17 | 0 | 0x18 | 0 | 0 |
| 18 | 0 | 0x18 | 0 | 0 |
| 19 | 0 | VARIABLE | 0 | 0 |
| 20 | 2 | 0 | 1 | 0 |
| 21 | 4 | 0 | 0 | 0 |
| 22 | 2 | 0 | 0 | 0 |
| 23 | 1 | 0 | 1 | 0 |
| 24 | 0 | VARIABLE | 0 | 0 |
| 25 | 1 | 0 | 1 | 0 |
| 26 | 0 | VARIABLE | 0 | VARIABLE |
| 27 | 0 | 0xa0 | 0 | 0 |
| 28 | 1 | 0 | 0 | 0xa0 |
| 29 | 2 | 0 | 0 | 0 |
| 30 | 1 | 0 | 0 | VARIABLE |
| 31 | 3 | 0 | 0 | 0 |
| 32 | 0 | 0 | 1 | 0 |
| 33 | 3 | 0 | 0 | 0 |
| 34 | 1 | 0 | 0 | 0xc68 |
| 35 | 2 | 0 | 1 | 0 |
| 36 | 1 | 0 | 2 | 0 |
| 37 | 2 | 0 | 0 | 0 |
| 38 | 1 | 0 | 4 | 0 |
| 39 | 5 | 0 | 0 | 0 |
| 40 | 0 | 0 | 0 | 0 |
| 41 | 1 | 0 | 0 | 0 |
| 42 | 4 | 0 | 0 | 0 |

## How the table was located

`tools/iosurf_dispatch.py` (in this repository) does the whole job on an extracted kext:

1. Walk `LC_SEGMENT_64`/`LC_SECTION_64` and keep `__DATA_CONST` and `__DATA`.
2. Scan in 4-byte steps for a run of 12 consecutive **plausible** records: the action decodes
   to a kernel address, scalar counts are ≤ 8, and each structure size is either `VARIABLE` or
   a 4-aligned value ≤ `0x20000`. This only locates an array; it does not number it.
3. Number it by content, not by guess: selectors 17 and 18 are adjacent rows with identical
   `(0, 0x18, 0, 0)`, so the first such pair inside the window fixes selector 0 at
   `pair − 17 × stride`.
4. Read 48 rows and print them.

Step 3 is what makes the result falsifiable rather than merely self-consistent: if the base is
wrong, the anchor pair is not where the arithmetic says it should be, and the tool says so on
stderr instead of printing a silently shifted table.

Four independent anchors have to agree before the numbering is believable:

| anchor | source | table row |
|---|---|---|
| sel 1 `release_surface` | disassembler | `(1, 0, 0, 0)` |
| sel 14 / 15 inc/dec use count | disassembler | `(2, 0, 0, 0)` |
| sel 17 `s_set_surface_notify` | wrapper `0xfffffff009bfd0c4`: loads `args+0x10`, `args+0x30` and `client+0xe8` | `(0, 0x18, 0, 0)` |
| sel 30 | **device**: one scalar in, no structure in, `kIOReturnNotPrivileged` rather than `kIOReturnBadArgument` | `(1, 0, 0, VARIABLE)` |

The strongest is sel 30. In a size sweep of 2640 calls it was the **only** one that got past the
dispatcher, and its outcome is exactly what the row predicts: one scalar in, no structure in,
and no fixed output size to violate — the three ways that layer can refuse a call are all
absent. A wrong row would have had to be wrong in all three fields at once and still land on
"not refused".

One detail of that validation is worth stating plainly, because it is easy to overstate: the
anchor pair 17/18 **alone** pins the numbering, since a one-row shift moves the pair off the
`pair − 17 × stride` address. The other four anchors are consistency checks — a shifted table
would still have to produce `(1,0,0,0)` at sel 1 and `(2,0,0,0)` at sel 14/15, which it would
not.

## The rule: input and output are both checked

`IOUserClient2022::dispatchExternalMethod` compares the incoming scalar counts and the two
structure sizes against the row, and rejects with `0xe00002c2`
(`kIOReturnBadArgument`) **before** calling the body. It does not care that the caller passed a
larger output buffer than needed "just in case": a non-zero output size on a row that declares
`0` is a mismatch.

Measured on the device, same connection, same payload:

| call | sizes sent | observed |
|---|---|---|
| sel 6 | 24-byte struct in, zero-length out | `kr=0xe00002c2` |
| sel 6 | 32-byte struct in, `0xc68` out | `kr=0`, surface id at `structOut+0x18` |
| sel 0 | 1 scalar, VARIABLE in, `0xc68` out | `kr=0`, surface id at `structOut+0x18` |
| sel 1 `release` | 1 scalar, no struct, no out | `0xe00002c2` — from the body, which looks the id up in the client map |
| sel 4 `lookup` | 1 scalar, `0xc68` out | `0xe00002c2` — from the body, same reason |

The second row is the one that matters: the only change between the two sel 6 calls is the pair
of sizes, and the only difference in outcome is pass/fail of the dispatcher. That is a
controlled comparison, not an inference.

`VARIABLE` is honestly narrower than "the size is not checked":

* at the dispatch layer, `VARIABLE` means no comparison — that is all it means;
* the bodies re-check, and they must. sel 2/3 require exact equality (`0xc` in, `0xc68` out)
  and return `0xe00002c2` themselves otherwise; sel 10/26 require at least 13 bytes in **and**
  out and treat the size as an in/out parameter; sel 19 caps the input at `0x1ff` and requires
  a NUL inside it.

So a `VARIABLE` row does not hand the body a raw length it copies blindly. It does move the
obligation, and that is where a future defect would live.

## Confirmed by device behaviour vs static only

Confirmed by a call from a sandboxed app on 24A446:

| sel | ABI | device evidence |
|---|---|---|
| 0 | `(1, VARIABLE, 0, 0xc68)` | `kr=0`; surface id readable at `structOut+0x18` |
| 6 | `(0, 0x20, 0, 0xc68)` | `kr=0`; the 24-byte/no-output variant refused with `0xe00002c2` |
| 14 / 15 | `(2, 0, 0, 0)` | `kr=0` |
| 17 | `(0, 0x18, 0, 0)` | `kr=0` with 24 bytes of structure input and no scalars; the registration call itself succeeds. Whether the callback ever fires is a separate question — see [docs/01](01-iosurface-112477.md) |
| 30 | `(1, 0, 0, VARIABLE)` | `0xe00002c1` `kIOReturnNotPrivileged` — dispatcher passed, body's entitlement gate refused |
| 1 | `(1, 0, 0, 0)` | `0xe00002c2`; static reading of the body (`FUN_9bff114`) shows it returns exactly that when the id is not in `client+0x140`, so the dispatcher had already passed |

Accepted at the dispatch layer but **not** driven to a successful body on the device:

| sel | ABI | what is and is not established |
|---|---|---|
| 10 | `(0, VARIABLE, 0, VARIABLE)` | `0xe00002c2` observed. The sweep did not separate a scalar-count refusal from a body refusal, so this row is *not* device-confirmed. Settle it by calling sel 10 with exactly zero scalars in and out, an input ≥ 13 bytes and an output ≥ 13 bytes: if it still returns `0xe00002c2`, the dispatcher is not the source and the payload is |
| 18 | `(0, 0x18, 0, 0)` | never called on the device. Static: the wrapper `0xfffffff009bfd0ec` mirrors 17 and targets the notify-remove body `0xfffffff009bf9/99c4`. Settle it by sending 24 bytes of structure and no scalars on a connection where a notify was registered with 17 |

Static only — the ABI is read from the table and the body was read separately, but no call was
made: 2, 3, 5, 7, 8, 9, 11, 12, 13, 16, 19–29, 31–42. For those, the sizes below are a
prediction, not a measurement. The two that matter for future work are 13 (writes `0x24` bytes
into a `0x28` declaration) and 28 (fills `0x84`, reports `0xa0`); both were read statically and
neither was exercised from the device.

Rows 43–47 are printed by the parser because its loop is fixed at 48. They are not selector
entries: the table measures 43. What those five records are is **not measured**; the experiment
that would settle it is to read the dispatch thunk's bound comparison in the 24A446 kernelcache
(the same technique that gave `bound 96` for the SEP/AMFI dispatchers).

## Known limitations of the parser

* The 48-row loop is not the table bound (see above).
* If the sel 17/18 anchor pair is missing, `parse_table` falls back to the plausibility anchor
  and the table is printed unvalidated. The tool warns on stderr but still exits 0, because a
  hard failure would also hide a table whose anchors moved for a legitimate reason. Check the
  warning.
* `KERNEL_BASE = 0xfffffff007004000` must match the artifact's image base. A mismatch does not
  produce an obviously wrong table — it produces a table whose anchor check fails, which is why
  the anchor check exists.
* Only rebase fixups (bit 63) are decoded. A bind entry would decode to `None`, fail the
  plausibility filter, and break the scan rather than being silently resolved to the wrong
  address. In this kext all 43 action pointers are rebases.

## What this does not give

The table says how to *reach* a handler; it says nothing about what the handler does with the
data. Knowing the sizes did not produce a memory primitive: with the ABI correct, the notify
channel still could not be armed, because surfaces created through sel 0/6 never appeared in
the client's surface map. That is a separate finding, recorded in
[docs/01](01-iosurface-112477.md).

## Reproducing

```sh
python tools/iosurf_dispatch.py "<path-to-kext>"
python tools/iosurf_dispatch.py "<path-to-kext>" --create-candidates
```

No binary is shipped here. Extract the kext from your own kernelcache
(`ipsw kernel extract` from a matching build) and point the tool at it.

No gate in `tools/gate.py` covers this table today: the gates re-check closures that have a
published evidence log behind them, and this is an ABI artifact rather than a closure. A gate
worth adding would assert the sel 17/18 anchor pair against the reader's own artifact and report
`SKIP` — not `PASS` — when the kext is absent, which is the correct answer for a reader without
the same build.

Provenance of the reading above: one local artifact, 314 376 bytes, sha256 prefix
`96ce38f0150a1127`, byte-identical under both local filenames it was kept under. The per-build
table addresses in the layout section come from a kernelcache-level scan, which is a different
measurement from this file-level one.
