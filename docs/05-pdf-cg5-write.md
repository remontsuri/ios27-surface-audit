# CoreGraphics type-5 shading — a write whose address is controlled and whose data is not

**Status:** closed as a primitive; stays open as a denial of service.
**Component:** CoreGraphics, `cg_shading_type5_draw` (PDF type-5/6/7 shading).

## Claim

Rendering a crafted PDF inside the system preview stack produces an out-of-bounds write to an
address derived from the document's shading parameters. The address is attacker-influenced; the
**data** written is a constant baked into the code (`0x3ff0000000000000` — the double `1.0`), not
a value taken from the file.

## How the write was found

A minimal PDF with a type-5 shading whose function dimension is larger than the number of
components the parser expects drives an index past the end of a coefficient array. The store is
a `str d2,[x14]` where `x14` comes from the shading mesh, and `d2` is the literal.

Cross-check: the address moved with the document parameters (that is what "controlled address"
means here), but every observed fault carried the same data register content.

## The control experiment

The decision hinged on whether the written value could be steered. Two documents were compared:
one with `C0 = C1 = 2.0` and a control with default values. Both produced the same fault payload
(`far = 0x3ff000000000001c`), and disassembly shows the constant loaded immediately before the
store:

```
mov x25, #0x3ff0000000000000
str d2,  [x14]
```

So the payload is the code's own constant. A write of `1.0` to a semi-chosen address is a crash
generator, not a memory-corruption primitive.

## Why the branch is still recorded as "closed"

Because the missing half — value control — has been looked for and not found: the shading
evaluator computes coefficients from the document, but the value that reaches this particular
store is the initialised constant. Until someone shows a document parameter that changes the
stored data, the branch cannot progress.

## Impact observed

Crashes in the preview/thumbnail extensions (in-process to the system UI, not to the kernel),
reproducible with a small PDF delivered as a file. That is a denial of service in a system
process and is documented here mainly so it is not mistaken for a write primitive.

## How to falsify this

Produce two documents that differ only in a parameter and observe two different data values at
the faulting store. Any dependence of `d2` on file content reopens the branch.
