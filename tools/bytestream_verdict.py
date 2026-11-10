"""bytestream_verdict.py - parse the ProbeFdWrite log (CVE-2026-112706).

The probe prints lines such as

    W|<label>|<pclass>|opts=0x201|direct_errno=1|fd=5|fl=0x1|wr=10|w_errno=0|size=0
    W|<label>|<pclass>|opts=0x201|direct_errno=1|REFUSED code=-12878
    METRIC|L_s2_fdwrite|write through bytestream|vended=3 write_attempted=5 write_ok=1 est=1|WRITE_OK

Only pure functions live here: they turn a line into a verdict, so they can be checked by a
mutation probe away from the device.

Where the expected values come from (not from the output of these functions):
  * errno values - Darwin <sys/errno.h>: EBADF=9, EACCES=13, EPERM=1, EROFS=30;
  * server codes - measured on the audited build: -12203 (sandbox deny while walking the
    target list) and -12878 (write attempt through the bytestream service);
  * F_GETFL mask - Darwin fcntl.h: O_ACCMODE=3, O_RDONLY=0, O_WRONLY=1, O_RDWR=2.
"""

# Darwin errno
EBADF = 9
EACCES = 13
EPERM = 1
EROFS = 30

# Codes returned by the bytestream service (measured on device and consistent with the
# public independent analysis of CVE-2026-112706: -12203 = path exists but is forbidden;
# -17913 = path absent; -16158 = opcode sealed as of 27.0; -12878 = write refused).
RC_SANDBOX_DENY = -12203
RC_WRITE_REFUSED = -12878
RC_NO_SUCH_FILE = -17913
RC_OPCODE_SEALED = -16158
# EEXIST passed through as-is: the server accepted O_CREAT|O_WRONLY and called open(2)
RC_EXISTS = 17

O_ACCMODE = 3
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2

# Path classes that do NOT belong to our own container.
ESCAPE_CLASSES = ("system", "root", "foreign")


def open_class(rc):
    """Classify an open result when the file was NOT vended."""
    if rc == RC_SANDBOX_DENY:
        return "sandbox_denied"       # path exists but is forbidden
    if rc == RC_WRITE_REFUSED:
        return "write_refused"
    if rc == RC_NO_SUCH_FILE:
        return "no_such_file"         # path absent (existence oracle)
    if rc == RC_OPCODE_SEALED:
        return "opcode_sealed"        # read/fdsc/getL sealed since 27.0
    if rc == RC_EXISTS:
        return "exists"
    return "unknown"


def access_mode(fl):
    """Access mode from F_GETFL (lowest two bits)."""
    m = fl & O_ACCMODE
    if m == O_RDONLY:
        return "rdonly"
    if m == O_WRONLY:
        return "wronly"
    if m == O_RDWR:
        return "rdwr"
    return "unknown"


def oracle_answer(rc):
    """Existence oracle: the server distinguishes "exists but forbidden" from "absent".

    This is the third capability of the primitive (after reading and directory listing),
    so it is encoded separately from the error class.
    """
    if rc == RC_SANDBOX_DENY:
        return "exists_forbidden"
    if rc == RC_NO_SUCH_FILE:
        return "absent"
    return "unknown"


ESCAPE_LABELS = ("var_tmp", "media_root", "itunes_dir", "etc_dir")


def parse_e_line(line):
    """Parse an E| line from the export probe (AVAssetExportSession)."""
    if not line.startswith("E|"):
        return None
    parts = line.split("|")
    out = {"label": parts[1]}
    for chunk in parts[2:]:
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            k = k.split()[-1]
            if k in ("status", "opened", "size"):
                try:
                    v = int(v)
                except ValueError:
                    pass
            out[k] = v
        else:
            out["note"] = chunk
    return out


def export_verdict(rows):
    """Verdict over the export lines.

    A control is mandatory: without a successful export into our own container, refusals
    outside prove nothing (the API may simply have been called incorrectly).
    """
    ctl = [r for r in rows if r.get("label") == "own_documents"]
    if not ctl:
        return "INCONCLUSIVE"
    c = ctl[0]
    if c.get("status") != 2 or c.get("opened") != 1 or c.get("size", 0) <= 0:
        return "INCONCLUSIVE"
    for r in rows:
        if r.get("label") in ESCAPE_LABELS and r.get("opened") == 1 and r.get("size", 0) > 0:
            return "WRITE_OUTSIDE"
    return "WRITE_DENIED_OUTSIDE"


def write_class(wr, err):
    """Classify the result of write(2) on a vended fd."""
    if wr > 0:
        return "wrote"
    if err == EBADF:
        return "bad_fd"
    if err == EROFS:
        return "readonly_fs"
    if err in (EACCES, EPERM):
        return "denied"
    return "other"


def write_is_escape(pclass, wr, match):
    """A write counts as a sandbox escape only outside our own container."""
    if wr <= 0 or not match:
        return False
    return pclass in ESCAPE_CLASSES


def parse_w_line(line):
    """Parse a W| line into a dict. Returns None for any other line."""
    if not line.startswith("W|"):
        return None
    parts = line.split("|")
    out = {"label": parts[1], "pclass": parts[2]}
    for chunk in parts[3:]:
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            out[k.split()[-1]] = v        # "REFUSED code=-12878" -> key "code"
        else:
            out["note"] = chunk
    if "code" in out:
        try:
            out["code"] = int(out["code"])
        except ValueError:
            pass
    for k in ("opts", "fl"):
        if k in out:
            try:
                out[k] = int(out[k], 16)
            except ValueError:
                pass
    for k in ("direct_errno", "fd", "wr", "w_errno", "size", "match"):
        if k in out:
            try:
                out[k] = int(out[k])
            except ValueError:
                pass
    return out


def summarise(rows):
    """Summary over all W lines: vended, written, whether an escape happened."""
    vended = 0
    wrote = 0
    escape = False
    bad_fd = 0
    for r in rows:
        if "fd" in r:
            vended += 1
            wc = write_class(r.get("wr", -1), r.get("w_errno", 0))
            if wc == "wrote":
                wrote += 1
                if write_is_escape(r["pclass"], r.get("wr", -1), r.get("match", 0)):
                    escape = True
            elif wc == "bad_fd":
                bad_fd += 1
    return {"vended": vended, "wrote": wrote, "bad_fd": bad_fd, "escape": escape}


def verdict(stats):
    """Final verdict from the summary."""
    if stats["escape"]:
        return "SANDBOX_WRITE_ESCAPE"
    if stats["wrote"] > 0:
        return "WRITE_OWN_ONLY"
    if stats["vended"] > 0 and stats["bad_fd"] > 0:
        return "READ_ONLY_FDS"
    return "WRITE_DENIED"


def main(argv):
    """python tools/bytestream_verdict.py <device.log> - table + verdict.

    Understands both formats: `W|...` (write probe through the bytestream service) and
    `E|...` (AVFoundation export probe).
    """
    import io as _io
    raw = _io.open(argv[1], encoding="utf-8", errors="replace").read().replace("\\n", "\n")
    lines = raw.split("\n")
    wrows = [r for r in (parse_w_line(l) for l in lines) if r]
    erows = [r for r in (parse_e_line(l) for l in lines) if r]

    if wrows:
        for r in wrows:
            if "code" in r:
                state = "refused:%s(%s)" % (open_class(r["code"]), r["code"])
            else:
                state = "fd=%s fl=%s wr=%s werr=%s" % (
                    r.get("fd"), hex(r.get("fl", 0)), r.get("wr"), r.get("w_errno"))
            print("  %-16s %-7s %s" % (r["label"], r["pclass"], state))
        stats = summarise(wrows)
        print("SUMMARY", stats)
        print("VERDICT", verdict(stats))

    if erows:
        for r in erows:
            print("  %-14s status=%s opened=%s size=%s %s" % (
                r["label"], r.get("status"), r.get("opened"), r.get("size"),
                r.get("err", "")))
        print("VERDICT", export_verdict(erows))

    if not wrows and not erows:
        print("no W|/E| lines found")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv))
