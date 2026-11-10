# -*- coding: utf-8 -*-
"""ave2_checks - interpretation rules for the AVE2 client-array measurements.

No binary parsing here: the module encodes how the `ProbeAveArr*` logs must be read,
plus one static fact (the aux array capacity), so that the conclusions can be checked
by tests and by a mutation probe instead of by prose.

Static fact (build 24A446, `AppleAVE2`, function 0xfffffff0084e4080):
    add  x22, x19, #0x55c          ; array base
    ldr  w9, [x22, x20, lsl #2]    ; 4-byte element, index x20
    ldrsw x8, [x19, #0x558]        ; client counter
    ldr  w8, [x19, #0x57c]         ; the field immediately after the array
    => +0x55c .. +0x57b = 0x20 = 8 elements of 4 bytes
"""

import re

#: Capacity of the auxiliary-layer-id array in the AVE2 structure (disassembly above).
AUX_CAPACITY = 8

#: Measurement line: "<tag> n=<int> set=<int>"
_SET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+n=(\d+)\s+set=(-?\d+)\s*$")

#: Encode line: "C_enc<idx>=<status> flags=<flags>"
_ENC_RE = re.compile(r"^C_enc(\d+)=(-?\d+)\s+flags=(-?\d+)\s*$")


def parse_sets(text):
    """Every property measurement in the log text -> set of (tag, n, status).

    Duplicates collapse: the probe writes the log incrementally, so the same line
    appears many times.
    """
    rows = set()
    for line in text.splitlines():
        m = _SET_RE.match(line.strip())
        if m:
            rows.add((m.group(1), int(m.group(2)), int(m.group(3))))
    return rows


def parse_encode(text):
    """Encode measurements -> {index: (status, flags)}."""
    out = {}
    for line in text.splitlines():
        m = _ENC_RE.match(line.strip())
        if m:
            out[int(m.group(1))] = (int(m.group(2)), int(m.group(3)))
    return out


def accepted(status):
    """Was the property accepted: OSStatus 0."""
    return status == 0


def max_accepted_n(rows, tag):
    """Largest accepted array size for this tag (0 - none)."""
    best = 0
    for t, n, st in rows:
        if t == tag and accepted(st) and n > best:
            best = n
    return best


def min_rejected_n(rows, tag):
    """Smallest rejected array size for this tag (0 - none rejected)."""
    best = 0
    for t, n, st in rows:
        if t == tag and not accepted(st):
            if best == 0 or n < best:
                best = n
    return best


def aux_capacity():
    """Capacity of the auxiliary-layer-id array in AVE2."""
    return AUX_CAPACITY


def overflow_reachable(max_n, capacity=None):
    """Is the overflow reachable: accepted size greater than the capacity."""
    cap = AUX_CAPACITY if capacity is None else capacity
    return max_n > cap


def encode_ok(enc):
    """Did every frame reach the encoder (status 0 and the "frame emitted" flag = 1)."""
    if not enc:
        return False
    for status, flags in enc.values():
        if status != 0:
            return False
        if (flags & 1) != 1:
            return False
    return True


def vector_closed(rows, tag):
    """Is the vector closed: VideoToolbox never accepts a size above the AVE2 capacity."""
    return not overflow_reachable(max_accepted_n(rows, tag))
