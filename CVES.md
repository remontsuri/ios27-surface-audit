# CVE register

Every CVE this audit touched, with the status of *our* measurement — not the vendor's.
A CVE can be real, public and still worthless for this goal (unreachable, wrong process,
or ending in a panic); the register says which.

Status vocabulary:

| Status | Meaning |
|---|---|
| **reproduced — DoS** | triggered on device; effect is termination, no controlled memory access |
| **reproduced — partial** | one half of the primitive reproduced (e.g. address but not value) |
| **measured — denied** | the described capability does not appear on this build |
| **measured — unreachable** | bug present, entry point not reachable from a sandboxed app |
| **documented only** | read from public material; not measured here |
| **not tested** | known, out of scope or out of window |

## Register

| CVE | Component | Class | Our status | Where |
|---|---|---|---|---|
| [CVE-2026-112477](cves/112477.md) | IOSurface notify | UAF | **reproduced — DoS** (1 of 6 device panics) | [docs/01](docs/01-iosurface-112477.md) |
| [CVE-2026-112706](cves/112706.md) | CoreMedia bytestream | sandbox escape (file read) | **reproduced — partial** (read yes, write no) | [docs/02](docs/02-bytestream-112706.md) |
| [CVE-2026-112688](cves/112688.md) | CoreMedia DV-RPU | OOB write (stack) | **reproduced — partial** (write yes, delivery no) | [cves/112688](cves/112688.md) |
| [CVE-2026-112705](cves/112705.md) | AppleAVE2 | missing bound → panic | **reproduced — DoS** | [docs/03](docs/03-ave2-temporal-layers.md) |
| [CVE-2026-112611](cves/112611.md) | CoreGraphics type-5 shading | OOB write + OOB read | **reproduced — partial** (address shaped by a double, value zero, not steerable) | [docs/08](docs/08-pdf-shading-sites.md) |
| [CVE-2026-86950](cves/86950.md) | CoreGraphics | OOB write | **reproduced — DoS** (crash, no primitive) | [cves/86950](cves/86950.md) · [docs/10](docs/10-imageio-tiff-planar.md) (adjacent decode-path branch) |
| [CVE-2026-113910](cves/113910.md) | kernel Compression (decmpfs) | kernel memory disclosure | **measured — denied** | [cves/113910](cves/113910.md) |
| [CVE-2026-112665](cves/112665.md) | kernel | KASLR / layout disclosure | **documented only** (no PoC to test) | [cves/112665](cves/112665.md) |
| [CVE-2026-28992](cves/28992.md) | IOHIDFamily FastPath | privileged user client | **measured — unreachable** | [cves/28992](cves/28992.md) |
| [CVE-2026-112476](cves/112476.md) | kernel | OOB read | **documented only** (corrected: not a leak) | [cves/112476](cves/112476.md) |

## Seen in the corpus, not measured here

These appear in public material or in tooling we read. Listing them is deliberate: it marks
what was *considered and set aside*, so a reader does not assume they were overlooked.

| CVE | Why it was not pursued |
|---|---|
| CVE-2026-112507 | `kern.ipc` notification path — requires a port namespace we do not control from a sandboxed app |
| CVE-2026-112576 | TOCTOU in a subsystem with no sandbox-reachable entry in our measurement |
| CVE-2026-64788, CVE-2026-64747, CVE-2026-64709 | out of the audited version window |
| CVE-2026-43748, CVE-2026-43724 | older release train |
| CVE-2026-84530, CVE-2026-84607, CVE-2026-65330, CVE-2026-65343, CVE-2026-65371 | reported after our build; no on-device check possible |
| CVE-2026-113950, CVE-2026-113912, CVE-2026-113897, CVE-2026-112692, CVE-2026-112690, CVE-2026-112684, CVE-2026-112633, CVE-2026-112625, CVE-2026-112614, CVE-2026-112468, CVE-2026-28990, CVE-2026-28952 | single mention; not enough public detail to build a check |
| CVE-2023-32434, CVE-2021-30955, CVE-2017-6979, CVE-2025-43300, CVE-2026-20687 | historical; fixed long before this build |

## How a CVE enters this register

1. A claim about a component and a class of bug (from public material).
2. A reachability check: can a sandboxed app reach the component at all.
3. A measurement, static or on device, with registers or object state.
4. A status from the vocabulary above, plus the falsifier.

A CVE without steps 2–3 never gets a status better than **documented only**, no matter how
serious the public description sounds.
