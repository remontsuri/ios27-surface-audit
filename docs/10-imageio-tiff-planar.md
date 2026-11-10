# ImageIO TIFF planar decode — the check 27.2 added, and why no file-driven trigger was found

**Status:** closed (negative) — the missing check is real on 24A446, but no file we can build makes
the scatter exceed the destination row.
**Component:** ImageIO, `TIFFReadPlugin::decodeTilePlanar` and `TIFFReadPlugin::decodeStripPlanar`.

| Field | Value |
|---|---|
| Class | out-of-bounds write (destination row vs. required scatter) |
| Build measured | iOS 27.0.1 (24A446), iPhone 14 (A15) |
| Comparison build | 27.2 (24B119) |
| Probes | [`probes/probe_tiff.c`](../probes/probe_tiff.c) |
| Related branch | [`docs/09`](09-cg-shading-r136-fixture.md) — the other file-driven decode-path OOB write in this audit |

## Claim

On 24A446 the planar TIFF decoders copy a decoded row into the destination without checking that
the destination row is large enough for what the planar scatter needs. 27.2 adds that check. If the
required size can be raised from the file — through `SamplesPerPixel`, `BitsPerSample`,
`PhotometricInterpretation`, tile geometry — the copy writes past the row on 24A446.

The branch is closed because the second sentence could not be made true with a file, not because
the first sentence is wrong.

## 1. The check that 27.2 added

Two log strings exist in 27.2 and have **zero** occurrences in 24A446:

```
*** ERROR: decodeTilePlanar destination row is %u bytes, the scatter needs %llu
*** ERROR: decodeStripPlanar destination row is %u bytes, the scatter needs %llu
```

while `decodeTilePlanar cannot handle %d bytes/component` is present in **both** builds — so the
function was not rewritten, a guard was inserted.

The pairing was established twice, independently:

| Function | 24A446 | 27.2 (24B119) |
|---|---|---|
| `TIFFReadPlugin::decodeTilePlanar(tiff*, IIODecodeInfo)` | `0x187d9a704` | `0x187d0f518` |
| `TIFFReadPlugin::decodeStripPlanar(tiff*, IIODecodeInfo)` | `0x187d9a020` | `0x187d0ed90` |

by symbol name, and then by cross-reference from the string to the same function body
(`adrp` at `0x187d0f960` lies inside `0x187d0f518..0x187d0f978`; for the strip path `adrp` at
`0x187d0f1a0` inside `0x187d0ed90..0x187d0f1b8`).

## 2. The code difference

27.2, at the top of the copy in `decodeTilePlanar`:

```c
if (uVar25 < *(uint *)(param_3 + 0x24) || (bool)uVar8) {
    /* copy the row into the destination */
} else {
    LogError("decodeTilePlanar", 0x8f9,
        "*** ERROR: decodeTilePlanar destination row is %u bytes, the scatter needs %llu\n");
}
```

24A446 has no such `if`. Its condition list matches 27.2 line for line up to
`if (((uVar9 & 0xffff) < 5) && …)`, after which the copy is reached directly through
`if (uVar4 < uVar17)` — the comparison of `uVar25` (destination row size) against
`*(IIODecodeInfo + 0x24)` (bytes the scatter requires) is simply not there.

Read as a contract: `need = (bits/8) × spp × tileWidth` against `dest_row`, which the plugin carries
at `+0x13c` and which reaches `IIODecodeInfo + 0x24`. On 24A446, making `need` bigger than
`dest_row` should therefore overrun the row.

## 3. Was the decoder actually reached?

Yes — this was the first thing to settle, because a negative result from a function that never runs
is worthless. The decoder is selected from a mode byte at `TIFFReadPlugin+0x240`, set in
`initialize` (`0x187951e20`):

```c
mode = 2;                                  /* stripChunky by default */
if (*(short *)(p + 0x14c) == 0) {
    if (*puVar2 == 6)                  mode = 6;
    else if (*(char *)(p + 0x249) == 1) mode = *(byte *)(p + 0x24a) | 4;
    else if (*(byte *)(p + 0x24a) != 0) mode = 3;
} else                                 mode = 1;
```

| mode | function |
|---|---|
| 1 | `decodeSubsampled` |
| 2 | `decodeStripChunky` |
| 3 | `decodeStripPlanar` |
| 4 | `decodeTileChunky` |
| 5 | `decodeTilePlanar` |
| 6 | `decodeRGBAImage` |

`+0x249` is `TIFFIsTiled()` and `+0x24a` is `PlanarConfiguration == 2` (both written in
`updateTiffStruct`). Tiled + planar therefore gives `1 | 4 = 5`, i.e. `decodeTilePlanar` — which is
what the fixtures set. So every fixture below did execute the function under test.

Callers, for completeness: `decodeTilePlanar` from `decodeImageImp` at `0x187953c90` (+0x248),
`decodeStripPlanar` from `0x187953b68` (+0x120), both direct calls, no table indirection.

## 4. What was run on the device

`probe_tiff.c` loads each file in `Documents/list.txt` and forces a real decode rather than reading
properties: `CGImageSourceCreateWithURL` → `CGImageSourceCreateImageAtIndex` → draw into an RGBA8
bitmap context → hash the pixels → then the thumbnail path separately (it has its own offset/length
checks). The log is flushed and `fsync`ed per line, and the cursor file is advanced **before** the
decode, so a crash cannot hide which file killed it.

29 fixtures, validity confirmed independently by two readers (`tifffile` and PIL):

* planar (`PlanarConfiguration = 2`) + tiled, `Compression = 1`;
* `SamplesPerPixel` 2, 3, 4, 5, 6, 8; `BitsPerSample` 8 and 16;
* `PhotometricInterpretation` 1, 2, 5, 8;
* tile size 16 and 32;
* a separate group where the tile is wider than the image: `tileWidth` 64, 128, 512, 2048 against
  `width = 16`, and `tileHeight = 64` against `height = 16`.

**Result: no crash, and every image decoded — including through the thumbnail path.** That includes
`p_tw2048_w16_spp3.tif`, where the tile width is 128× the image width.

The only refusal was `bps = 64` (planar, tiled): properties reported `w = -1 h = -1` and
`CGImageSourceCreateImageAtIndex` returned NULL — rejected before the copy, not during it.

### Second series: tag inconsistency instead of geometry

Since `need` is a product, the other factor is the sample count. Fixtures where
`BitsPerSample`'s `count` disagrees with `SamplesPerPixel`:

| file | declared | result |
|---|---|---|
| `q_bpscount1_spp8.tif` | count 1, spp 8 | decoded, no crash |
| `q_bpscount1_spp4.tif` | count 1, spp 4 | decoded, no crash |
| `q_bpscount2_spp8.tif` | count 2, spp 8 | parser refusal (`w = -1`, image NULL) |
| `q_bpscount3_spp1.tif` | count 3, spp 1 | decoded, no crash |
| `m_bps24_planar_tile*.tif` | 24 bits per component | accepted as depth 32, 96 bpp, no crash |

No new crash reports were produced by either series.

## 5. Why this closes the branch

The guard 27.2 added compares `uVar25` against `IIODecodeInfo + 0x24`. On the paths we can drive,
`dest_row` is not smaller than `need`:

* it is not a value the file sets directly — no `str`/`stp` writes either `+0x24` of
  `IIODecodeInfo` or `+0x13c` of the plugin explicitly; it arrives by copying a descriptor block,
  and in practice lands at or above what the scatter needs;
* neither factor of `need` could be pushed past it: raising sample count, bit depth, or tile
  geometry by up to two orders of magnitude left every decode inside its row.

So the defect is present and the guard is a real hardening change, but the precondition of the
guard — `need > dest_row` — was not satisfiable from a file in this measurement. That is a
different statement from "the bug is not there", and it is the one this note makes.

## 6. What is not measured

* **Where `dest_row` comes from.** It was not found as an explicit store into either offset, so the
  statement "it is copied from the descriptor block" is an inference from its absence, not a traced
  data flow. Settle it by tracing `IIODecodeInfo + 0x24` forward from the allocation of the
  `IIODecodeInfo` in `decodeImageImp`.
* **The strip path.** The paired decompilation of `decodeStripPlanar` did not complete, so nothing
  is claimed about strip beyond the fact that the guard string exists in 27.2 and not in 24A446.
  Settle it by decompiling `0x187d9a020` (24A446) and `0x187d0ed90` (27.2).
* **A non-file entry.** Re-decoding into an already-sized buffer, or a caller that passes its own
  `IIODecodeInfo`, could reach the same copy with a smaller destination row. That is a different
  attack surface and was not tested.

## 7. Falsifiers

| To reopen the branch | What must be shown |
|---|---|
| file-driven trigger | one TIFF, tiled and planar, that makes `need > dest_row` and produces an over-write or a crash report on 24A446 |
| the guard's precondition | a decode where 27.2 emits `destination row is %u bytes, the scatter needs %llu` on input that 24A446 accepts — that is the exact input class this branch needs |
| the `dest_row` origin | a store into `IIODecodeInfo + 0x24` or `TIFFReadPlugin + 0x13c` that a file-influenced value can reach |
| strip path | a strip-planar fixture that behaves differently from the tile fixtures above |

The second row is the cheapest experiment: it turns "we could not build the input" into a concrete
target, because the build that rejects it also names the two numbers it compared.

## 8. Which CVE this is, and which it is not

The class matches the ImageIO entries of the 27.2 security notes — class "out-of-bounds write",
remedy "improved bounds checking" — for ImageIO. It is **not** the CoreGraphics glyph/PDF path of
[CVE-2026-86950](../cves/86950.md), which is a different component and a different fault site; the
CVE register links here from that row only because both branches are file-driven decode-path OOB
writes measured the same way, and 86950's own status lives in its CVE file. This branch is recorded
here rather than in a CVE file because no single identifier could be tied to the function pair with
the material at hand.
