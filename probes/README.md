# Probe sources

These are the sources of the on-device probes that produced the evidence in this repository.
They are kept because a measurement without the code that produced it is just a claim.

## What is here

| File | What it measures | Document |
|---|---|---|
| `probe_iorace.c` | IOSurface notification race (selector 17 vs client teardown) | [docs/01](../docs/01-iosurface-112477.md) |
| `probe_fdleak.c` | bytestream service: which paths it will vend a descriptor for | [docs/02](../docs/02-bytestream-112706.md) |
| `probe_fdwrite3.c` | bytestream service: write attempts with a corrected control | [docs/02](../docs/02-bytestream-112706.md) |
| `probe_avearr3.c` | AVE2 auxiliary-layer-id arrays: count boundary, values, real encode | [docs/03](../docs/03-ave2-temporal-layers.md) |
| `probe_ifc.c` | interface enumeration and link-layer address lengths | [docs/04](../docs/04-rtm-scrub-infoleak.md) |
| `probe_rpu2.c` | Dolby Vision RPU block grammar and the overflow in the parser | [cves/112688](../cves/112688.md) |
| `probe_cm4.c` | the same overflow through the exported CFDataRef entry point | [cves/112688](../cves/112688.md) |
| `gen_rpu.py` | generates the RPU payloads used above | [cves/112688](../cves/112688.md) |
| `rpu_payloads.h` | generated payload arrays (output of `gen_rpu.py`) | — |

## How they were built and run

These are not ordinary apps. On the audit device each probe was:

1. compiled for `arm64e` against the platform headers, with `nostdlib`-style declarations in the
   places where the SDK was not available;
2. signed with a personal development identity;
3. installed over USB, launched, and held while it ran (the process is killed as soon as the
   controlling session ends);
4. read back from its own log file inside the app container.

The signing identity, the provisioning profile, the install/relay infrastructure and the personal
endpoint are **not** part of this repository. Two probes (`probe_avearr3.c`, `probe_rpu2.c`) include
a local logging header that provided `open`/`write`/`unlink` wrappers plus an optional HTTP POST to
that endpoint; that header is intentionally withheld because it embeds a private address. Replace it
with your own logging helpers of the same shape, or compile with plain `printf` to the device
console.

## What these probes are not

They are not exploits. Every one of them measures a condition and reports numbers; the closures in
[`../CVES.md`](../CVES.md) are conclusions drawn from those numbers, and each conclusion names the
observation that would overturn it.

## Expectation management

Running a probe requires a development-signed app on your own device and a working USB path to it.
Without that, these files are readable documentation of method rather than something you can
execute in place.
