#!/usr/bin/env python3
"""Read the IOExternalMethodDispatch2022 table of the IOSurface kext.

Why: an IOKit selector is only reachable if the caller passes the exact scalar
counts and structure sizes the table declares. Without the table, "the selector
returns kIOReturnBadArgument" cannot be told apart from "the selector does not
exist" - and that ambiguity cost this audit several weeks.

Entry layout (XNU, iokit/IOKit/IOUserClient.h), 40 bytes, stride 0x28:
  +0x00  IOExternalMethodAction function    arm64e chained fixup -> VA
  +0x08  uint32 checkScalarInputCount
  +0x0c  uint32 checkStructureInputSize     (0xFFFFFFFF = kIOUCVariableStructureSize)
  +0x10  uint32 checkScalarOutputCount
  +0x14  uint32 checkStructureOutputSize
  +0x18  uint8  allowAsync                  (+7 bytes of alignment)
  +0x20  const char *checkEntitlement

The 16 bytes after the four size fields are not padding: +0x18 reads as 0/1 and
is 1 exactly for the two asynchronous selectors (17 and 40), and +0x20 is NULL
for every entry in this kext. Read the stride as "40-byte record", not
"24-byte record plus 16 bytes of slack" - the stride is the same either way, but
the second reading invites the wrong conclusion that per-selector entitlements
are declared here.

Ground truth anchors used to validate the scan (all from the disassembler or from
device behaviour, never from this table):
  sel  1 release_surface       (1, 0,    0, 0)
  sel 14 inc_use_count         (2, 0,    0, 0)
  sel 15 dec_use_count         (2, 0,    0, 0)
  sel 17 set_surface_notify    (0, 0x18, 0, 0)
  sel 18 remove_surface_notify (0, 0x18, 0, 0)
  sel 30 accepted one scalar on the device and refused with
         kIOReturnNotPrivileged, never with kIOReturnBadArgument:
         (1, 0, 0, VARIABLE)

Usage:
    python tools/iosurf_dispatch.py <path-to-kext>
    python tools/iosurf_dispatch.py "<path-to-kext>" --create-candidates

The kext is not distributed with this repository: extract it from your own
kernelcache. The default argument is a placeholder, so running this without an
artifact fails with a message rather than with a traceback.
"""

import argparse
import struct
import sys

KERNEL_BASE = 0xFFFFFFF007004000
MH_MAGIC_64 = 0xFEEDFACF
STRIDE = 0x28
VARIABLE = 0xFFFFFFFF  # kIOUCVariableStructureSize
NOTIFY_ROW = (0, 0x18, 0, 0)  # sel 17 and sel 18 are adjacent and identical
DEFAULT_KEXT = "<path-to-kext>"

# The table's own width is 43 entries (0..42), measured by a separate scan of the
# kernelcache. This loop is deliberately fixed at 48: the parser does not know
# the bound, and rows 43..47 are printed for inspection but are not selector
# entries until something else attributes them.
PRINTED_ROWS = 48


def load_sections(path):
    """Return (data, {('__SEG','__sect'): (fileoff, size, va)})."""
    with open(path, "rb") as f:
        data = f.read()
    magic, = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        raise ValueError("not a 64-bit Mach-O: 0x%x" % magic)
    ncmds, = struct.unpack_from("<I", data, 16)
    off = 32
    sections = {}
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            nsects, = struct.unpack_from("<I", data, off + 64)
            soff = off + 72
            for _ in range(nsects):
                sect = data[soff:soff + 16].rstrip(b"\0").decode()
                size, = struct.unpack_from("<Q", data, soff + 40)
                foff, = struct.unpack_from("<I", data, soff + 48)
                va, = struct.unpack_from("<Q", data, soff + 32)
                sections[(segname, sect)] = (foff, size, va)
                soff += 80
        off += cmdsize
    return data, sections


def decode_ptr(raw):
    """arm64e chained fixup -> VA; otherwise None."""
    if raw >> 63:
        return KERNEL_BASE + (raw & 0xFFFFFFFF)
    if 0xFFFFFFF000000000 <= raw <= 0xFFFFFFFFFFFFFFFF:
        return raw
    return None


def read_row(data, pos):
    raw, = struct.unpack_from("<Q", data, pos)
    a, b, c, d = struct.unpack_from("<IIII", data, pos + 8)
    return {"action": decode_ptr(raw), "scalar_in": a, "struct_in": b,
            "scalar_out": c, "struct_out": d}


def _plausible(row):
    act = row["action"]
    if not act or not (0xFFFFFFF000000000 <= act <= 0xFFFFFFFFFFFFFFFF):
        return False
    if row["scalar_in"] > 8 or row["scalar_out"] > 8:
        return False
    for v in (row["struct_in"], row["struct_out"]):
        if v != VARIABLE and (v > 0x20000 or v % 4):
            return False
    return True


def parse_table(path):
    """Return (base_va, rows); rows[i] is the entry for selector i."""
    data, sections = load_sections(path)
    spans = [(foff, size, va) for (seg, _), (foff, size, va) in sections.items()
             if seg in ("__DATA_CONST", "__DATA")]
    if not spans:
        return None, []
    foff0 = spans[0][0]

    # Step 1: find a run of consecutive plausible records. Any run will do; the
    # selector number is not known yet, so this only locates the array.
    anchor = None
    for foff, size, va in spans:
        for p in range(foff, foff + size - 12 * STRIDE, 4):
            if all(_plausible(read_row(data, p + i * STRIDE)) for i in range(12)):
                anchor = p
                break
        if anchor:
            break
    if anchor is None:
        return None, []

    # Step 2: number the array. sel 17 and sel 18 are adjacent identical rows, so
    # the first such pair inside the candidate window fixes selector 0.
    base = None
    for delta in range(-6, 10):
        p = anchor + delta * STRIDE
        if p < foff0:
            continue
        r1, r2 = read_row(data, p), read_row(data, p + STRIDE)
        if (r1["scalar_in"], r1["struct_in"], r1["scalar_out"], r1["struct_out"]) == NOTIFY_ROW and \
           (r2["scalar_in"], r2["struct_in"], r2["scalar_out"], r2["struct_out"]) == NOTIFY_ROW:
            base = p - 17 * STRIDE
            break
    if base is None:
        # Fallback: no anchor pair. The table printed from here is unvalidated;
        # main() says so on stderr.
        base = anchor

    base_va = None
    for foff, size, va in spans:
        if foff <= base < foff + size:
            base_va = va + (base - foff)
            break

    rows = []
    for i in range(PRINTED_ROWS):
        r = read_row(data, base + i * STRIDE)
        r["sel"] = i
        rows.append(r)
    return base_va, rows


def find_create_candidates(rows):
    """Selectors with a fixed structure input - candidates for a create-style call.

    This is a filter, not a verdict: it says "this selector takes a structure of a
    known size", which is where a surface-creating call must live. It does not
    say which one creates anything.
    """
    return [r for r in rows if r["struct_in"] not in (0, VARIABLE)]


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Decode the IOExternalMethodDispatch2022 table of the IOSurface kext.")
    ap.add_argument("kext", nargs="?", default=DEFAULT_KEXT,
                    help="Mach-O kext extracted from your own kernelcache "
                         "(default: %s)" % DEFAULT_KEXT)
    ap.add_argument("--create-candidates", action="store_true",
                    help="also list selectors that take a fixed-size structure input")
    args = ap.parse_args(argv)

    try:
        base, rows = parse_table(args.kext)
    except OSError as exc:
        print("cannot read %s: %s" % (args.kext, exc), file=sys.stderr)
        print("extract the kext from your own kernelcache and pass its path; "
              "no binary is shipped with this repository", file=sys.stderr)
        return 2
    if base is None:
        print("table not found", file=sys.stderr)
        return 1

    row17 = rows[17]
    anchored = (row17["scalar_in"], row17["struct_in"],
                row17["scalar_out"], row17["struct_out"]) == NOTIFY_ROW
    if not anchored:
        print("warning: the sel 17/18 anchor pair was not found; the base below "
              "comes from the plausibility scan and is NOT validated",
              file=sys.stderr)

    print("table VA=0x%x stride=0x%x" % (base, STRIDE))
    for r in rows:
        print("sel %2d  sc_in=%d st_in=0x%-4x sc_out=%d st_out=0x%-4x  action=0x%x"
              % (r["sel"], r["scalar_in"], r["struct_in"], r["scalar_out"],
                 r["struct_out"], r["action"] or 0))

    if args.create_candidates:
        cands = find_create_candidates(rows)
        print("fixed-structure-input selectors: %s"
              % ", ".join(str(r["sel"]) for r in cands))
    return 0


if __name__ == "__main__":
    sys.exit(main())
