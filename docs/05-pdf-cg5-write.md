# PDF type-5 shading — summary of the primitive

| Field | Value |
|---|---|
| Component | CoreGraphics, `cg_shading_type5_draw` (PDF type-4/5/6/7 shading) |
| Class | out-of-bounds write **and** out-of-bounds read |
| Our status | **reproduced — partial**: address shaped by a double from the file, value fixed, no steering to a real mapping |
| Build | iOS 27.0.1 (24A446), iPhone 14 (A15) |
| Detail | [`docs/08`](08-pdf-shading-sites.md) — sites, statistics, emulator, limit |

## In one paragraph

A malformed type-5 shading drives an index past the end of a coefficient array. Two sites fault:
a write that stores **32-bit zero** at `bits(double) + 0x1c`, and a read that loads **16 bytes from
`bits(double)`** and copies them into the shading output. The "double" is a value produced by the
PDF shading function, so the address is file-influenced while the written data is constant. The
address cannot be aimed at a real mapping, because a PDF real is bounded near 1e±38 and a kernel or
low userland address is not representable — measured, not assumed (see `docs/08` §6).

## What is and is not claimed

* **Is:** a reproducible out-of-bounds access in a system rendering process, with the faulting
  address derived from a value in the document, and a read whose result is placed in the renderer's
  output.
* **Is not:** a write of attacker-chosen data, or an access to an attacker-chosen real address.

An earlier version of this note described the write as `str d2,[x14]` with a constant `1.0`. That
was a wrong model of the site; instruction-level reading plus an independent emulator replaced it
with `str wzr,[x22,#0xc]`. The correction is recorded here on purpose: the earlier wording is what
made the bug look closer to a primitive than it is.

## Impact as it stands

Crashes in the system preview extension, reached by handing it a normal file. A userland denial of
service in a system process; not a kernel primitive.

## The 27.2 difference

27.2 adds a dimension check in the shading initialiser (`CG-SEC-187882049: invalid function for type
5 shading`), so malformed shadings of this shape are rejected there. On 27.0.1 the check is absent.

## Falsifiers

| To reopen the branch | What must be shown |
|---|---|
| write value | the stored value is not zero at the write site |
| steering | a document makes the site fault at an address that is a real mapping |
| leak | the 16 bytes read reach data the caller can read back |

The third one is the interesting one and has not been tested.
