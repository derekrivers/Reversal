#!/usr/bin/env python3
"""Reject private inputs and original instruction fragments in R29-B authored files."""
import argparse
import gzip
import json
from pathlib import Path

from extract_tactical_word_29 import extract

FILES = [
    "evidence/tactical-word-29-sites.json",
    "evidence/tactical-word-29-oracle.json.gz",
    "evidence/tactical-word-29-negative.json",
    "evidence/tactical-word-29-findings.json",
    "evidence/tactical-word-29-annotations-proposal.json",
    "evidence/tactical-word-29-privacy.json",
    "reports/tactical-word-29.md",
    "reconstruction/tactical-word-29.ts",
    "reconstruction/check-tactical-word-29.ts",
    "scripts/extract_tactical_word_29.py",
    "scripts/emulate_tactical_word_29.py",
    "scripts/check_tactical_word_29_negative.py",
    "scripts/check_tactical_word_29_privacy.py",
]

MAX_EXPANDED_BYTES = 16 * 1024 * 1024


def scan_authored(path, bodies, max_expanded_bytes=MAX_EXPANDED_BYTES):
    authored = path.read_bytes()
    payloads = [authored]
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rb") as stream:
            expanded = stream.read(max_expanded_bytes + 1)
        if len(expanded) > max_expanded_bytes:
            raise ValueError("expanded authored file exceeds privacy scan limit: " + str(path))
        payloads.append(expanded)
    for payload in payloads:
        lower = payload.lower()
        for body in bodies:
            for at in range(len(body) - 15):
                fragment = body[at:at + 16]
                if fragment in payload or fragment.hex().encode() in lower:
                    raise ValueError("original PE fragment in " + str(path))


def run(exe, exports, preflight):
    root = Path(__file__).resolve().parents[1]
    sites = extract(exe, exports, preflight)
    specimen = exe.read_bytes()
    bodies = [specimen[int(f["file_offset"], 16):int(f["file_offset"], 16)+42]
              for f in sites["functions"]]
    for name in FILES:
        path = root / name
        if not path.is_file() or path.suffix.lower() in (".exe", ".asm", ".c", ".gpr", ".zip", ".rep"):
            raise ValueError("missing or forbidden authored path " + name)
        scan_authored(path, bodies)
    return {"work_unit": "R29-B", "status": "passed", "specimen_sha256": sites["specimen_sha256"],
            "authored_files_scanned": len(FILES), "files": FILES,
            "checks": ["task-specific authored paths and extensions",
                       "bounded gzip expansion for compressed authored files",
                       "no raw or contiguous hex-encoded 16-byte fragment of either original body in stored or expanded bytes"],
            "limitation": "Scoped code-fragment scan supplements staged-content review; it is not a general secret detector."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    a.output.write_text(json.dumps(run(a.exe, a.exports, a.preflight), indent=2)+"\n", encoding="utf-8", newline="\n")
