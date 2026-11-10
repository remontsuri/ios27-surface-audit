"""Тесты классификатора bytestream-пробы. Значения — из errno-констант Darwin и
измеренных кодов сервера, а не из вывода SUT (gutcheck IRON LAW)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.bytestream_verdict import (
    EBADF,
    EACCES,
    EROFS,
    access_mode,
    open_class,
    oracle_answer,
    parse_e_line,
    export_verdict,
    parse_w_line,
    summarise,
    verdict,
    write_class,
    write_is_escape,
)


def test_open_class_measured_sandbox_deny():
    assert open_class(-12203) == "sandbox_denied"


def test_open_class_measured_write_refusal():
    assert open_class(-12878) == "write_refused"


def test_open_class_other_code_is_unknown():
    assert open_class(-5) == "unknown"


def test_open_class_eexist_means_write_path_accepted():
    # code=17 (EEXIST) сервер отдал на O_CREAT|O_WRONLY: путь открывался, файл уже был
    assert open_class(17) == "exists"


def test_open_class_app_container_deny():
    # -17913 = пути НЕТ (оракул существования), а не «контейнер запрещён»:
    # так помечен TRAV AppContainer в логе 03.11 — путь с неверным числом ../ не существовал
    assert open_class(-17913) == "no_such_file"


def test_open_class_opcode_sealed():
    assert open_class(-16158) == "opcode_sealed"


def test_oracle_answer_distinguishes_forbidden_from_absent():
    assert oracle_answer(-12203) == "exists_forbidden"
    assert oracle_answer(-17913) == "absent"


def test_oracle_answer_unknown_on_success():
    assert oracle_answer(0) == "unknown"


def test_export_verdict_inconclusive_without_control():
    rows = [parse_e_line("E|own_documents|status=3|opened=1|size=144")]
    assert export_verdict(rows) == "INCONCLUSIVE"


def test_export_verdict_inconclusive_when_control_missing():
    rows = [parse_e_line("E|var_tmp|status=4|opened=0|size=-1")]
    assert export_verdict(rows) == "INCONCLUSIVE"


def test_export_verdict_denied_when_control_ok_and_outside_closed():
    rows = [parse_e_line("E|own_documents|status=2|opened=1|size=9000"),
            parse_e_line("E|var_tmp|status=4|opened=0|size=-1"),
            parse_e_line("E|itunes_dir|status=4|opened=0|size=-1")]
    assert export_verdict(rows) == "WRITE_DENIED_OUTSIDE"


def test_export_verdict_write_outside_when_file_appeared():
    rows = [parse_e_line("E|own_documents|status=2|opened=1|size=9000"),
            parse_e_line("E|itunes_dir|status=2|opened=1|size=72000")]
    assert export_verdict(rows) == "WRITE_OUTSIDE"


def test_access_mode_bits_from_fcntl():
    assert access_mode(0x0000) == "rdonly"
    assert access_mode(0x0001) == "wronly"
    assert access_mode(0x0002) == "rdwr"


def test_access_mode_ignores_high_flags():
    # O_APPEND=0x8 поверх O_WRONLY
    assert access_mode(0x0009) == "wronly"


def test_write_class_ebadf_is_9():
    assert write_class(-1, EBADF) == "bad_fd"
    assert EBADF == 9


def test_write_class_readonly_fs():
    assert write_class(-1, EROFS) == "readonly_fs"


def test_write_class_permission():
    assert write_class(-1, EACCES) == "denied"


def test_write_class_success_needs_positive_count():
    assert write_class(10, 0) == "wrote"


def test_write_is_escape_requires_system_class():
    assert write_is_escape("system", 10, 1) == True
    assert write_is_escape("root", 10, 1) == True


def test_write_is_escape_rejects_own_container():
    assert write_is_escape("own", 10, 1) == False


def test_write_is_escape_requires_content_match():
    assert write_is_escape("system", 10, 0) == False


def test_parse_w_line_extracts_fields():
    r = parse_w_line("W|prefs_dir|system|opts=0x201|direct_errno=1|fd=7|fl=0x1|wr=10|w_errno=0|size=0")
    assert r["label"] == "prefs_dir"
    assert r["pclass"] == "system"
    assert r["opts"] == 0x201
    assert r["fl"] == 0x1
    assert r["wr"] == 10
    assert r["fd"] == 7


def test_parse_w_line_refused_code():
    r = parse_w_line("W|etc_dir|root|opts=0x201|direct_errno=13|REFUSED code=-12878")
    assert r["code"] == -12878
    assert r["direct_errno"] == 13


def test_parse_w_line_ignores_metric():
    assert parse_w_line("METRIC|L_s2_fdwrite|x|y|WRITE_OK") is None


def test_summarise_counts_own_write_as_not_escape():
    rows = [parse_w_line("W|own|own|opts=0x201|direct_errno=0|fd=3|fl=0x1|wr=10|w_errno=0|size=0"),
            parse_w_line("W|own|own|READBACK n=10 match=1")]
    rows[0]["match"] = 1
    s = summarise([r for r in rows if r])
    assert s["vended"] == 1
    assert s["wrote"] == 1
    assert verdict(s) == "WRITE_OWN_ONLY"


def test_verdict_escape_wins_over_own_write():
    r = parse_w_line("W|prefs|system|opts=0x201|direct_errno=1|fd=7|fl=0x1|wr=10|w_errno=0|size=0")
    r["match"] = 1
    s = summarise([r])
    assert verdict(s) == "SANDBOX_WRITE_ESCAPE"


def test_verdict_read_only_when_write_hits_bad_fd():
    own = parse_w_line("W|own_rdonly_ctl|own|opts=0x0|direct_errno=0|fd=3|fl=0x0|wr=-1|w_errno=9|size=0")
    s = summarise([own])
    assert s["bad_fd"] == 1
    assert verdict(s) == "READ_ONLY_FDS"


def test_verdict_denied_when_nothing_vended():
    s = summarise([parse_w_line("W|etc|root|opts=0x201|direct_errno=13|REFUSED code=-12203")])
    assert verdict(s) == "WRITE_DENIED"
