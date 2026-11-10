# PDF type-5 shading: the two fault sites, the value-control experiment, and the measured limit

Detailed companion to [`docs/05`](05-pdf-cg5-write.md). Everything here is from the shipping
CoreGraphics of iOS 27.0.1 (24A446) plus crash reports produced on the device; the arithmetic was
re-derived with an independent emulator, not taken from the decompiler.

## 1. Method

1. Every crash report whose process was the PDF probe or the system preview extension was pulled
   (63 reports) and reduced to the tuple `{far, x24, x28, x10, esr, offset}`.
2. The function was located in the disassembler and its two faulting sites were read at
   instruction level.
3. **Independent oracle:** an emulator executes the *real bytes* of the shipping binary at both
   sites with the register values taken from the reports. If the model is wrong, the emulated
   `far` disagrees with the device.

That third step is what makes the numbers below evidence rather than inference.

## 2. The function and the two sites

```
_cg_shading_type5_draw   entry 0x183d741a4   size 3004 bytes
```

### Write site — `func+0x740`

```
0x183d748dc  stur x24,[x8, #-0x100]
0x183d748e0  add  x22, x24, x28, LSL #0x4      ; x22 = x24 + (x28 << 4)
0x183d748e4  str  wzr, [x22, #0xc]             ; <-- fault; wzr = 32-bit zero
```

So the written value is **a constant zero**, and the address is derived from `x24` and `x28`.
Byte sequence at the site: `df 0e 00 b9`.

### Read site — `func+0x7AC`

```
0x183d74948  add  x21, x23, x8, LSL #0x3       ; destination = x23 + x8*8
0x183d7494c  ldr  x9, [x19, x24, LSL #0x3]     ; x9 = *(x19 + x24*8)  <-- out-of-bounds slot load
0x183d74950  ldr  q0, [x9]                     ; <-- fault: 16 bytes at x9
0x183d74954  str  q0, [x21]                    ; and copied straight into the output array
```

Here `x24` indexes past the end of an array, the over-read slot is used as a **pointer**, and the
16 bytes read from it are copied into the shading output.

## 3. What the 63 reports say

| | read path | write path |
|---|---|---|
| reports | 43 | 20 |
| sub-offset from `cg_shading_type5_draw` | `1964` (25), none (18, older build) | `1856` (**20/20**) |
| `x28` | `0` (25) | `1` (**20/20**) |
| `x10` (range counter R) | 2, 150, 160, 170, 176, 180, 256 | `136` (**20/20**) |

The write formula `far == x24 + x28*16 + 0xc` holds in **20 of 20** reports; on the read path it
holds in **0 of 43**.

Across every write report, `far - x24` is `0x1c` (20 of 20).

### 3.1 Value control (write path)

Eight different doubles were placed in the shading function output; twenty reports:

| double | `far` |
|---|---|
| 0.5010186901960784 | `0x3fe008585922762d` |
| 1.0 | `0x3ff000000000001c` |
| 2.0 | `0x400000000000001c` |
| 1024.0 | `0x409000000000001c` |
| 4369.0 | `0x40b111000000001c` |
| 16705.0 | `0x40d050400000001c` |
| 20000.0 | `0x40d388000000001c` |
| 50000.0 | `0x40e86a000000001c` |

In all eight: `far = bits(double) + 0x1c`. The address is the **IEEE-754 bit pattern of a number
produced by the shading function**, not a decoded coordinate.

### 3.2 Where the address comes from: two hypotheses, one survives

* **H1** — the address comes from a decoded vertex coordinate (`x14 = [x12+0x38] + [x12+0x20]*v`).
  Prediction: with `/Decode 100…1600` the addresses would cluster in
  `0x4059000000000000..0x4099000000000000`.
  Result: **0 of 25** reports fall in that band.
* **H2** — the address is `bits(double)` of the shading function's output.
  Result: **25 of 25** explained — 10× `bits(16705.0)`, 10× `bits(0.5)`, 4× `bits(1.0)`, 1× `0x0`.

H1 is falsified by its own prediction; H2 is confirmed. The coordinate and `/Decode` do not steer
anything.

## 4. Emulator check

```
=== write site: str wzr,[x22,#0xc], x22 = x24 + x28*16 ===
16705.0            emulated 0x40d050400000001c   report 0x40d050400000001c   OK
4369.0             emulated 0x40b111000000001c   report 0x40b111000000001c   OK
1.0                emulated 0x3ff000000000001c   report 0x3ff000000000001c   OK
2.0                emulated 0x400000000000001c   report 0x400000000000001c   OK
1024.0             emulated 0x409000000000001c   report 0x409000000000001c   OK
20000.0            emulated 0x40d388000000001c   report 0x40d388000000001c   OK
50000.0            emulated 0x40e86a000000001c   report 0x40e86a000000001c   OK
0.5010186901960784 emulated 0x3fe008585922762d   report 0x3fe008585922762d   OK
```

The read path reproduces as well, including the empty slot (`0x0`), which is how a NULL deref
appears in the same batch.

## 5. So what is the primitive, exactly

* **Write:** four bytes of **zero**, at `bits(double) + 0x1c` (with `x28 = 1`, as in every report).
  Address influenced by file content; data fixed.
* **Read:** sixteen bytes from `bits(double)`, **copied into the shading output**. That second half
  is the interesting one: it is shaped like an info leak — a controlled address read whose result is
  placed in data the renderer produces.

## 6. The measured limit (why this stops here)

To use either half you must be able to write a *useful 64-bit address* as a double that the PDF
shading function will emit. A proving attempt was built: a Type-4 function `{ pop 1.32624737e-315 }`,
a denormal whose bit pattern is `0x0000000010000000`, so the write site should have faulted at
`0x000000001000001c` and the read site at `0x10000000`.

On a clean build (the earlier binary carried a fault-absorbing oracle and was therefore invalid for
this test) the fixture rendered three times **without any fault**, while the control fixture with an
ordinary double still produced the canonical report (`far=0x40d050400000001c`, `x28=1`, byte write,
`+1856`).

The reason is expressiveness, not luck: PDF reals are bounded near 1e±38, while a kernel address or
a low userland address is not a representable PDF real. Values inside the range behave one way,
values outside decay to zero — and zero is the one "address" that cannot help. So the site can write
`0` to addresses shaped like doubles, and read from addresses shaped like doubles; it cannot be aimed
at a real mapping.

## 7. Delivery

The faulting renderer in the system path is **in-process**: the preview extension renders the
document itself, which is why the crashes land in the extension rather than in a separate daemon.
Documents reached it through a normal file hand-off; no special API was needed.

That matters for the chain question: there is no privileged daemon to land in, so the primitive
stays in the process that already has the user's file access.

## 8. The 27.2 difference

Between the audit build and 27.2 the shading initialiser gained a component check:

```
27.2    if ((4 < components) || (fn_dim != components)) bail
        "CG-SEC-187882049: invalid function for type 5 shading (range dimension does not match color space)"
24A446  no such check; the initialiser computes components << 1 and reads Decode for 2*components+4
```

So the malformed-shading family is closed by input validation in 27.2, and open on 27.0.1.

## 9. Falsifiers

* **Write value:** show a document whose stored value is non-zero at the write site (breaks "zero
  write").
* **Steering:** show a PDF that makes the site fault at an address that is a real mapping (breaks
  the expressiveness limit in §6).
* **Leak:** show the 16 bytes read at the read site reaching data the caller can read back (turns
  the read half into an actual info leak).

Any one of these reopens the branch; the third is the one worth trying first.
