# -*- coding: utf-8 -*-
"""Тесты к tools/ave2_checks.py — на реальных строках логов проб AveArr 1..3.

Логи встроены литералами, а не читаются из out/live/: staging-копия для
мутационной пробы не включает каталог out/, и тест, читающий файл, там падал бы.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.ave2_checks import (
    parse_sets,
    parse_encode,
    accepted,
    max_accepted_n,
    min_rejected_n,
    aux_capacity,
    overflow_reachable,
    encode_ok,
    vector_closed,
)

# --- реальные строки из out/live/probe_avearr3_device.log (12 503 -> 2 410 Б) ---
LOG3 = """AVEARR3 create=0 ctrl_ntl2=0
A_normal n=9 set=-12900
A_normal n=10 set=-12900
A_normal n=12 set=-12900
A_normal n=16 set=-12900
B_hi63 n=8 set=-12900
B_normal n=8 set=-12900
B_hi300 n=8 set=-12900
B_negative n=8 set=-12900
C_pre_set n=8 set=-12900
C_enc0=0 flags=1
C_enc1=0 flags=1
C_enc2=0 flags=1
"""

# --- реальные строки из out/live/probe_avearr2_device.log ---
LOG2 = """HEVCAuxiliaryIDs n=1 set=0
HEVCAuxiliaryIDs n=2 set=0
HEVCAuxiliaryIDs n=3 set=0
HEVCAuxiliaryIDs n=8 set=0
HEVCAuxiliaryIDs n=17 set=-12900
HEVCAuxiliaryLayerIDs n=1 set=0
HEVCAuxiliaryLayerIDs n=2 set=0
HEVCAuxiliaryLayerIDs n=3 set=0
HEVCAuxiliaryLayerIDs n=8 set=0
HEVCAuxiliaryLayerIDs n=17 set=-12900
"""


def test_parse_sets_reads_all_four_phase_a_rows():
    assert parse_sets(LOG3) == {
        ("A_normal", 9, -12900),
        ("A_normal", 10, -12900),
        ("A_normal", 12, -12900),
        ("A_normal", 16, -12900),
        ("B_hi63", 8, -12900),
        ("B_normal", 8, -12900),
        ("B_hi300", 8, -12900),
        ("B_negative", 8, -12900),
        ("C_pre_set", 8, -12900),
    }


def test_parse_sets_dedupes_repeated_rows():
    twice = LOG3 + LOG3
    assert len(parse_sets(twice)) == len(parse_sets(LOG3))


def test_accepted_only_for_zero_status():
    assert accepted(0) == True
    assert accepted(-12900) == False
    assert accepted(-19032) == False


def test_max_accepted_n_is_zero_when_everything_rejected():
    assert max_accepted_n(parse_sets(LOG3), "A_normal") == 0


def test_max_accepted_n_for_aux_layer_ids_is_eight():
    assert max_accepted_n(parse_sets(LOG2), "HEVCAuxiliaryLayerIDs") == 8


def test_min_rejected_n_for_aux_layer_ids_is_seventeen():
    assert min_rejected_n(parse_sets(LOG2), "HEVCAuxiliaryLayerIDs") == 17


def test_aux_capacity_is_eight_elements():
    assert aux_capacity() == 8


def test_overflow_not_reachable_at_capacity():
    assert overflow_reachable(8) == False


def test_overflow_reachable_one_past_capacity():
    assert overflow_reachable(9) == True


def test_vector_closed_for_aux_layer_ids():
    assert vector_closed(parse_sets(LOG2), "HEVCAuxiliaryLayerIDs") == True


def test_parse_encode_returns_three_frames():
    assert parse_encode(LOG3) == {0: (0, 1), 1: (0, 1), 2: (0, 1)}


def test_encode_ok_requires_flag_one():
    assert encode_ok(parse_encode(LOG3)) == True


def test_encode_ok_false_when_flag_missing():
    assert encode_ok({0: (0, 0)}) == False


def test_encode_ok_false_when_status_nonzero():
    assert encode_ok({0: (-12900, 1)}) == False
