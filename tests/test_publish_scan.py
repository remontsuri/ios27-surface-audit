"""Tests for the publication scanner.

Expected rule names, line numbers and exit codes come from the documented contract in
tools/publish_scan.py ("Exit code: 0 = clean, 1 = findings") and from the rule table
itself - not from a previous run of the scanner.

Every fixture is an obvious fake. No real key, host or identifier appears here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.publish_scan import allowed, main, scan_file

# Deliberately fake: matches the "openai-key" pattern, is not a credential.
# Assembled from two parts on purpose: the scanner scans this file too, and a literal
# key-shaped string in a tracked file is a finding it must report. The runtime value
# below is what lands in the temporary fixtures and trips the rule; the source text
# never contains a key-shaped token.
FAKE_KEY = "sk-" + "TEST-not-a-real-key-0123456789"

# "closed" in Cyrillic. Written as escapes so this file stays pure ASCII: the
# repository rule is that no Cyrillic appears anywhere, test fixtures included.
CYRILLIC_WORD = "\u0437\u0430\u043a\u0440\u044b\u0442\u043e"


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_planted_api_key_is_reported_as_openai_key(tmp_path):
    path = _write(tmp_path, "notes.txt", "key = " + FAKE_KEY + "\n")
    hits = scan_file(path)
    assert len(hits) == 1
    assert hits[0]["rule"] == "openai-key"
    assert hits[0]["line"] == 1


def test_planted_api_key_makes_the_scan_exit_nonzero(tmp_path, capsys):
    path = _write(tmp_path, "leak.txt", FAKE_KEY + "\n")
    rc = main(["publish_scan.py", path])
    out = capsys.readouterr().out
    assert rc == 1
    assert "RESULT: BLOCKED" in out


def test_markdown_line_with_cyrillic_is_a_language_finding(tmp_path):
    path = _write(tmp_path, "note.md", "status: " + CYRILLIC_WORD + "\n")
    hits = scan_file(path)
    assert len(hits) == 1
    assert hits[0]["rule"] == "language"
    assert hits[0]["line"] == 1


def test_same_cyrillic_line_in_a_text_file_is_not_a_language_finding(tmp_path):
    # The language rule is scoped to Markdown by design; a .txt fixture with the same
    # bytes must produce nothing, which proves the scope is real and not accidental.
    path = _write(tmp_path, "note.txt", "status: " + CYRILLIC_WORD + "\n")
    assert scan_file(path) == []


def test_plain_english_file_produces_no_findings(tmp_path):
    path = _write(tmp_path, "clean.md", "# Title\n\nPlain English text, no identifiers.\n")
    assert scan_file(path) == []


def test_allowlisted_paths_are_recognised(tmp_path):
    assert allowed("tools/publish_scan.py") is True
    assert allowed("tools/gate.py") is False
    assert allowed(os.path.join("tests", "test_publish_scan.py")) is False


def test_allowlisted_file_with_planted_key_is_skipped(tmp_path, capsys):
    # Control first: the same bytes are a finding when scanned directly, so this test
    # fails if the allowlist stops working - it is not a test that cannot fail.
    path = _write(tmp_path, os.path.join("tools", "publish_scan.py"), FAKE_KEY + "\n")
    assert [h["rule"] for h in scan_file(path)] == ["openai-key"]
    rc = main(["publish_scan.py", path])
    out = capsys.readouterr().out
    assert rc == 0
    assert "findings 0" in out
    assert "RESULT: CLEAN" in out
