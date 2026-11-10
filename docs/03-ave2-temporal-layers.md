# AppleAVE2 encoder — array IDs and temporal layers rejected before the kernel

**Status:** closed — client-controlled counters never reach the kernel arrays.
**Components:** VideoToolbox session properties (userland), `com.apple.driver.AppleAVE2` (kernel).

## Claim

Two related hypotheses were tested and both die in userland:

1. **Auxiliary layer ID arrays.** Passing a client-supplied count with IDs above the array
   capacity should overflow a 32-byte kernel array. VideoToolbox rejects the values first.
2. **Temporal layer count (CVE-2026-112705).** On the audit build the encoder has no runtime
   check for `iNumberOfTemporalLayers`; the consequence is a kernel panic, not a controlled write,
   and the crash site reported publicly for a different SoC does not reproduce here.

## Measurement 1 — capacity gate

Sweeping the two properties that accept layer-ID arrays, with counts from 2 to 300:

```
A_normal  n=9   set=-12900
A_normal  n=16  set=-12900
B_hi63    n=8   set=-12900
B_hi300   n=8   set=-12900
B_negative n=8  set=-12900
```

`-12900` is `kVTPropertyNotSupportedErr`, returned in userland before any XPC to the encoder
service. Static confirmation: the kernel side reads the count from a fixed offset and compares it
against a capacity derived from the same structure — the array is `8 × 4` bytes and the property
accepts at most 8 entries (`MVHEVCVideoLayerIDs` accepts exactly 2).

So the "client count vs kernel array" pair is consistent *by construction*: the only values that
pass the userland filter are the ones the kernel array can hold.

## Measurement 2 — temporal layers

The build's encoder has no runtime bound for `iNumberOfTemporalLayers` (asserts are compiled out
in release). Driving the encoder with out-of-range counts produces reproducible kernel panics in
the encoding daemon; the register state at fault (`x0=0x59`, `FAR=0x59`) shows a null-ish pointer
derived from a small integer, not attacker-controlled memory.

That is a denial of service. It does not read or write memory at a chosen address, and the panics
stop the device, which makes it a poor primitive even as a stepping stone.

## Measurement 3 — what 27.2 adds

Diffing the encoder's assert strings between builds shows 19 new runtime checks in 27.2 covering
HEVC VPS/SPS/PPS counts, the auxiliary arrays and the temporal-layer range. Their existence
confirms the shape of the checks that the audit build lacks — and also confirms that the vendor
treats all of them as input validation, not as memory-safety fixes.

## Conclusion

The encoder is a genuine attack surface with real bugs, but the ones reachable from a sandboxed
app end in a panic. The controllable-array hypothesis is disproved by the userland capacity check,
not by a failed attempt.

## How to falsify this

* Get a layer-ID array with more entries than the kernel array capacity past
  `kVTPropertyNotSupportedErr`.
* Produce a non-panic outcome from an out-of-range temporal-layer count.
