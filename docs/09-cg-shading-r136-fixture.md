# The `crash_shading_r136.pdf` fixture: object structure, the R sweep, and what 27.2 added

| Field | Value |
|---|---|
| Component | CoreGraphics — `_CGPDFShadingType5Init` (`0x183d73c34`) and `_cg_shading_type5_draw` (`0x183d741a4`) |
| Fixture | `crash_shading_r136.pdf`, 1908 bytes, sha256 prefix `450835921a947d2e` |
| Build measured | iOS 27.0.1 (24A446), iPhone 14 (A15) |
| Comparison build | 27.2 (24B119) |
| Companion | [`docs/05`](05-pdf-cg5-write.md) (the primitive), [`docs/08`](08-pdf-shading-sites.md) (the two fault sites and the measured limit) |

This note is about **one input file** and the three questions it answers: why the object is
inconsistent, why the number of shading-function outputs decides whether the renderer survives, and
which validation the later build added. The fault sites themselves are in
[`docs/08`](08-pdf-shading-sites.md) and are not repeated here.

## 1. The file

One page, 200 × 200, one resource `/Sh1`, content stream `/Sh1 sh`. Two objects matter:

```
5 0 obj
<< /ShadingType 5 /ColorSpace /DeviceGray
   /BitsPerCoordinate 32 /BitsPerComponent 8
   /VerticesPerRow 2 /Decode [0 200 0 200 0 1]
   /Function 6 0 R /Length 36 >>
stream
  4 vertices of (x:32 bits, y:32 bits, component:8 bits) = 288 bits = 36 bytes
endstream

6 0 obj
<< /FunctionType 2 /Domain [0 1] /N 1
   /C0 [1 1 1 … 136 values] /C1 [1 1 1 … 136 values]
   /Range [0 1 0 1 … 136 pairs = 272 numbers] >>
```

Four vertices with `/VerticesPerRow 2` is two rows of two: the geometry is consistent. The
decoding triple (32, 32, 8) needs exactly 36 bytes, which is what the stream holds. The `/Decode`
array has six numbers, which is `2 * components + 4` for one colour component — also consistent.
The inconsistency is in object 6.

## 2. Where the object is inconsistent: `/N 1` against 136 declared outputs

A PDF type-2 (exponential) function with `/N 1` is a one-dimensional function between two points,
so it is supposed to carry exactly one `C0`, one `C1`, and one `Range` pair. This object declares
`/N 1` and then 136 `C0` values, 136 `C1` values and 272 `Range` numbers.

That is not the "DeviceN with more than four components" shape that
[`docs/05`](05-pdf-cg5-write.md) discusses. Here the colour space is a single-component
`DeviceGray` and the mismatch is between **the number of outputs the function declares** and **the
number of components the colour space has**. Those are two different numbers, and on 24A446 nothing
compares them.

The number 136 is not decorative. The draw loop's range counter (`x10` in the crash reports) was
**136 in 20 of 20** write-path reports, and the journal line for this very fixture is
`cg.shading → render R=136`. So `R`, the quantity that decides the fate of the render, is read out
of the fixture's own `/C0`/`/C1`/`/Range` arrays — not from `/N`.

## 3. What the initialiser does on 24A446

`_CGPDFShadingType5Init` @ `0x183d73c34`:

1. validates `BitsPerCoordinate` / `BitsPerComponent` against the mask `0x1116`;
2. reads `/VerticesPerRow`, `/Decode` and `/Function`;
3. builds the shading function through `_CGPDFShadingCreateShadingFunction` @ `0x183f94ee4`;
4. **does not compare the function's output dimension with the colour-space component count.**

In the region where the component dimension is handled, the only comparison present is a single
`cmp w8, #0x7` with its branch (`0x183d73e14…0x183d73e78`). Three things are absent there:

* no `cmp …, #4` — nothing bounds the component count;
* no second `cmp` of one counter against another — nothing ties the function dimension to the
  component count;
* the decode side is derived from the component count alone (`components << 1`, then
  `2 * components + 4` entries read from `/Decode`), which is exactly why the six-number `/Decode`
  above passes while the 136-output function does not get checked against anything.

The consequence is that the shading object is accepted, and the draw path later iterates over a
dimension larger than the array it writes into.

## 4. Why R=4 survives, R=8 dies, R=136 faults

The draw loop is the one described in [`docs/08`](08-pdf-shading-sites.md) §5.4: one 16-byte record
per step, a field at `+0xc` written unconditionally, filling of the coordinate array gated by
`idx < *(local_120 + 0x48)`. With a 16-byte stride and a `+0xc` field offset:

| R | bytes touched past the record base (`0xc + 16·(R−1) + 4`) | observed |
|---|---|---|
| 4 | 64 | **survived** (`cg.shading.sweep`) |
| 8 | 128 | **died** (`cg.shading.sweep`) |
| 136 | 2176 | **died** — 20 of 20 write-path crash reports carry `x10 = 136` |

So the array is dimensioned from the colour space (one record for `DeviceGray`) while the loop runs
over the function's declared output count. At R=4 the overshoot stays inside the frame's slack; at
R=8 it no longer does and the process faults; at R=136 it is two kilobytes past any plausible slack,
which is why that value produces reports every single time.

What the crash report shows at that point is not "the 136th record" but the derived address: `far`
equals the bit pattern of a double produced by the shading function, plus a fixed offset
(`docs/08` §3.1 and §4). In other words, by the time the loop is in the overrun region, the slot it
reads is holding function output rather than geometry — the same mechanism as in `docs/08`, reached
from the same fixture shape.

## 5. What the 27.2 check closes

27.2 moves the initialiser to `0x183c5c88c` and adds, at `0x183c5cacc`:

```
0x183c5cacc  cmp  x9, #0x4
0x183c5cad0  b.hi <fail>          ; more than four components  -> reject
0x183c5cad4  cmp  x10, x9
0x183c5cad8  b.ne <fail>          ; function dim != components  -> reject
```

with the diagnostic `CG-SEC-187882049: invalid function for type 5 shading (range dimension does
not match color space)` (quoted in [`docs/08`](08-pdf-shading-sites.md) §8).

Both halves are needed, and both are absent on 24A446:

* `x9 ≤ 4` rejects the "many components in a colour space that has few" family;
* `x10 == x9` rejects **this** fixture, whose component count is 1 and whose function dimension is
  136.

So the r136 shape is not a surviving input on 27.2 — it is rejected before the draw. That is worth
recording precisely because the file is often cited as a live trigger: on 27.0.1 it is one, on 27.2
it is not, and the reason is a check in the initialiser rather than in the drawing code.

## 6. What is not measured

* **Where the boundary sits between R=4 and R=8.** The sweep recorded those two endpoints only.
  R=5, 6 and 7 were not run. Settle it by running the same generator at each R on 24A446 and
  recording the first value that yields a crash report.
* **The frame offset of the record base.** The published decompilation pins the *read* array
  (`local_b0`, `x19 = x29 − 0xa0`) but not the destination base of the write loop, so the
  "64 bytes fit, 128 do not" statement above is arithmetic on the stride, not a measured frame
  map. Settle it by reading the `sub sp` / `x29` offsets for the destination array in
  `cg_shading_type5_draw`.
* **Why the function dimension is taken from the array lengths rather than `/N`.** The register
  evidence (20/20 with `x10 = 136`) says that is what happens; the code path that decides it was
  not disassembled to the instruction. Settle it with a fixture that keeps `/N 1` but declares a
  different number of `C0` values and observing which number reaches `x10`.
* **A rendered result.** Nothing here says what the page looks like when it does not crash; the
  fixture is used as an input, not as an output comparison.

## 7. Falsifiers

| To reopen or overturn this document | What must be shown |
|---|---|
| "R=136 faults on 24A446" | the same fixture rendering without producing a crash report on the audit build |
| the 4/8 boundary | R=8 surviving, or R=4 producing a report, in a repeat of the sweep |
| the counter's origin | a fixture with `/N 1` and a different `C0` count reaching the draw loop with `x10 = 1`, which would move this file into the ordinary type-2 case |
| the 27.2 attribution | a 27.2 render of this fixture that reaches `cg_shading_type5_draw` instead of being rejected by `0x183c5cacc` |

The last one is the one to run first if a later build is available: it is a single render and it
tests the only claim in §5 that is about behaviour rather than about bytes.

## 8. Provenance

The fixture and the sweep journal come from the same collection as the other PDF material in this
audit; the static claims are addresses and instruction bytes read out of the shipping CoreGraphics
of the two builds. The full probe log for the render that produced the r136 journal line is not
published here. Regenerating a fixture of this shape does not need the original binary:
[`probes/gen_cg_fingerprint.py`](../probes/gen_cg_fingerprint.py) emits a type-5 shading with a
chosen output count. It is a comparable fixture rather than a byte-for-byte copy — it uses 16-bit
coordinates where the original uses 32 — so the sweep should be repeated with it before treating
the two as interchangeable.
