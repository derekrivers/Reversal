#!/usr/bin/env python3
"""Reject original-body fragments and private artifacts in R27-A authored files."""
import argparse
import json
from pathlib import Path

from extract_iterator_helpers_27 import extract

FILES = [
    "evidence/iterator-helpers-27-sites.json",
    "evidence/iterator-helpers-27-oracle.json.gz",
    "evidence/iterator-helpers-27-negative.json",
    "evidence/iterator-helpers-27-findings.json",
    "evidence/iterator-helpers-27-annotations-proposal.json",
    "evidence/iterator-helpers-27-privacy.json",
    "reports/iterator-helpers-27.md",
    "reconstruction/iterator-helpers-27.ts",
    "reconstruction/check-iterator-helpers-27.ts",
    "scripts/extract_iterator_helpers_27.py",
    "scripts/emulate_iterator_helpers_27.py",
    "scripts/check_iterator_helpers_27_negative.py",
    "scripts/check_iterator_helpers_27_privacy.py",
]


def main(exe, exports, preflight):
    root = Path(__file__).resolve().parents[1]
    sites = extract(exe, exports, preflight)
    data = exe.read_bytes()
    bodies = [data[int(f["file_offset"], 16):int(f["file_offset"], 16) + f["body_bytes"]]
              for f in sites["functions"]]
    for name in FILES:
        path = root / name
        if not path.is_file() or path.suffix.lower() in (".exe", ".zip", ".gpr", ".rep", ".asm", ".c"):
            raise ValueError("missing or forbidden authored file: " + name)
        authored = path.read_bytes()
        lower = authored.lower()
        for body in bodies:
            for at in range(len(body) - 15):
                fragment = body[at:at + 16]
                if fragment in authored or fragment.hex().encode() in lower:
                    raise ValueError("original-body fragment in " + name)
    return {"work_unit": "R27-A", "status": "passed",
            "specimen_sha256": sites["specimen_sha256"],
            "authored_files_scanned": len(FILES), "files": FILES,
            "checks": ["task-specific authored paths and allowed extensions",
                       "no raw or contiguous hex-encoded 16-byte fragment from either 19-byte original body"],
            "limitation": "Scoped code-fragment scan supplements review; it is not a general secret detector."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    a.output.write_text(json.dumps(main(a.exe, a.exports, a.preflight), indent=2) + "\n", encoding="utf-8", newline="\n")
