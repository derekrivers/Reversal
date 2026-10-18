#!/usr/bin/env python3
"""Extract reproducible PE layout and string anchors without executing the game."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

def inspect(path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not MZ")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("not PE")
    machine, count, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe+4)
    optional = pe+24
    if struct.unpack_from("<H", data, optional)[0] != 0x10b:
        raise ValueError("this script expects PE32")
    entry = struct.unpack_from("<I", data, optional+16)[0]
    base = struct.unpack_from("<I", data, optional+28)[0]
    sections = []
    for n in range(count):
        pos = optional+optional_size+40*n
        name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<8sIIII", data, pos)
        sections.append(dict(name=name.rstrip(b"\0").decode("ascii", errors="replace"), rva=rva,
                             virtual_size=virtual_size, raw_size=raw_size, raw_offset=raw_offset))
    def va(offset):
        for s in sections:
            if s["raw_offset"] <= offset < s["raw_offset"]+s["raw_size"]:
                return f"0x{base+s['rva']+offset-s['raw_offset']:08x}"
        return None
    paths, anchors = [], []
    keys = {"index.dat", "player.dat", "3.9.68", "match_eng.cpp", "match_events.cpp", "match_pl.cpp", "tactics.cpp", "database.cpp"}
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        text = match.group().decode("ascii")
        item = dict(file_offset=f"0x{match.start():x}", virtual_address=va(match.start()), text=text)
        lower = text.lower()
        if "\\code\\" in lower and lower.endswith((".cpp", ".c")):
            paths.append(item)
        if lower in keys or lower.rsplit("\\",1)[-1] in keys:
            anchors.append(item)
    return dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), machine=f"0x{machine:x}",
                coff_timestamp=timestamp, characteristics=f"0x{characteristics:x}", image_base=f"0x{base:x}",
                entry_point=f"0x{base+entry:x}", sections=sections, embedded_source_paths=paths, anchors=anchors,
                limitations=["Strings identify candidates, not behavior", "No game execution", "Version marker does not establish pristine patch state"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.binary), indent=2))
