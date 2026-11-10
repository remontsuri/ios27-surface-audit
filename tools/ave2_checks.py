# -*- coding: utf-8 -*-
"""ave2_checks — интерпретация измерений по клиентским массивам AVE2.

Здесь нет разбора бинарей: модуль кодирует ПРАВИЛА чтения логов проб
`ProbeAveArr*` и один статический факт (ёмкость aux-массива), чтобы выводы
были проверяемы тестами и мутационной пробой, а не пересказом.

Статический факт (24A446, `AppleAVE2`, функция 0xfffffff0084e4080):
    add  x22, x19, #0x55c          ; база массива
    ldr  w9, [x22, x20, lsl #2]    ; элемент 4 байта, индекс x20
    ldrsw x8, [x19, #0x558]        ; счётчик
    ldr  w8, [x19, #0x57c]         ; следующее поле сразу за массивом
    => +0x55c .. +0x57b = 0x20 = 8 элементов по 4 байта
"""

import re

#: Ёмкость массива auxiliary layer id в структуре AVE2 (из дизассемблера, см. docstring).
AUX_CAPACITY = 8

#: Строка замера: "<tag> n=<int> set=<int>"
_SET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s+n=(\d+)\s+set=(-?\d+)\s*$")

#: Строка кодирования: "C_enc<idx>=<status> flags=<flags>"
_ENC_RE = re.compile(r"^C_enc(\d+)=(-?\d+)\s+flags=(-?\d+)\s*$")


def parse_sets(text):
    """Все замеры свойств из текста лога -> множество (tag, n, status).

    Дубликаты схлопываются: проба пишет лог инкрементально, поэтому одна и та же
    строка встречается много раз.
    """
    rows = set()
    for line in text.splitlines():
        m = _SET_RE.match(line.strip())
        if m:
            rows.add((m.group(1), int(m.group(2)), int(m.group(3))))
    return rows


def parse_encode(text):
    """Замеры кодирования -> {index: (status, flags)}."""
    out = {}
    for line in text.splitlines():
        m = _ENC_RE.match(line.strip())
        if m:
            out[int(m.group(1))] = (int(m.group(2)), int(m.group(3)))
    return out


def accepted(status):
    """Принято ли свойство: OSStatus 0."""
    return status == 0


def max_accepted_n(rows, tag):
    """Наибольший принятый размер массива для данного tag (0 — ни один)."""
    best = 0
    for t, n, st in rows:
        if t == tag and accepted(st) and n > best:
            best = n
    return best


def min_rejected_n(rows, tag):
    """Наименьший отбитый размер массива для данного tag (0 — таких нет)."""
    best = 0
    for t, n, st in rows:
        if t == tag and not accepted(st):
            if best == 0 or n < best:
                best = n
    return best


def aux_capacity():
    """Ёмкость массива auxiliary layer id в AVE2."""
    return AUX_CAPACITY


def overflow_reachable(max_n, capacity=None):
    """Достижимо ли переполнение: принятый размер больше ёмкости."""
    cap = AUX_CAPACITY if capacity is None else capacity
    return max_n > cap


def encode_ok(enc):
    """Все ли кадры ушли в энкодер (status 0 и флаг «кадр выдан» = 1)."""
    if not enc:
        return False
    for status, flags in enc.values():
        if status != 0:
            return False
        if (flags & 1) != 1:
            return False
    return True


def vector_closed(rows, tag):
    """Закрыт ли вектор: VT не принимает размер больше ёмкости AVE2."""
    return not overflow_reachable(max_accepted_n(rows, tag))
