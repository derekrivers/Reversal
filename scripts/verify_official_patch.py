#!/usr/bin/env python3
"""Compare a CM 01/02 specimen with the executable in one pinned 3.9.68 updater.

This reads the updater's ZIP and file-length table. It never executes the updater,
inner setup.exe, or game. The decoder is deliberately specific to this archive.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import urllib.request
import zipfile

COMMIT = "befe35e79ccedeafc17dbf56054afcae9143ab27"
URL = f"https://raw.githubusercontent.com/cm0102-linux/cm0102-linux/{COMMIT}/patches/official-3.9.68.exe"
INSTALLER_SHA256 = "b3f2b7d2ace6e86d0974e5ad68ae7a87a1e8fc3494c90d00cc3758392dcf24f1"
EXPECTED_UPDATE_BYTES = 306794850
MEMBER_COUNT = 46

def digest(data):
    return hashlib.sha256(data).hexdigest()

def validate_pe(image):
    if image[:2] != b"MZ":
        raise ValueError("payload is not MZ")
    pe = struct.unpack_from("<I", image, 0x3c)[0]
    if image[pe:pe+4] != b"PE\0\0":
        raise ValueError("payload is not PE")
    machine, sections, _, _, _, optional_bytes, _ = struct.unpack_from("<HHIIIHH", image, pe+4)
    optional = pe+24
    if machine != 0x14c or struct.unpack_from("<H", image, optional)[0] != 0x10b:
        raise ValueError("expected x86 PE32")
    file_extent = struct.unpack_from("<I", image, optional+60)[0]
    for i in range(sections):
        section = optional+optional_bytes+40*i
        raw_size, raw_pointer = struct.unpack_from("<II", image, section+16)
        file_extent = max(file_extent, raw_pointer+raw_size)
    if file_extent != len(image):
        raise ValueError("PE section extent differs from the declared payload length")

def compare(installer, current):
    if digest(installer) != INSTALLER_SHA256:
        raise ValueError("unexpected updater SHA-256; this decoder only admits the pinned archive")
    with zipfile.ZipFile(io.BytesIO(installer)) as archive:
        info = archive.getinfo("update.dat")
        if info.file_size != EXPECTED_UPDATE_BYTES:
            raise ValueError("unexpected update.dat size")
        # Reading the complete member also checks its ZIP CRC.
        update = archive.read("update.dat")
        setup = archive.read("setup.exe")
        members = [{"name": x.filename, "bytes": x.file_size, "crc32": f"{x.CRC:08x}"} for x in archive.infolist()]
    header_bytes = MEMBER_COUNT*4
    lengths = struct.unpack_from(f"<{MEMBER_COUNT}I", update)
    if header_bytes+sum(lengths) != len(update):
        raise ValueError("file-length table does not partition the whole payload")
    positions = []
    offset = header_bytes
    for index, size in enumerate(lengths):
        positions.append({"index": index, "offset": offset, "bytes": size})
        offset += size
    normal = update[header_bytes:header_bytes+lengths[0]]
    gdi_offset = header_bytes+lengths[0]
    gdi = update[gdi_offset:gdi_offset+lengths[1]]
    validate_pe(normal)
    validate_pe(gdi)
    if normal[0x6d4394:0x6d439a] != b"3.9.68":
        raise ValueError("missing expected 3.9.68 marker")
    if b"Version 3.9.68" not in setup or b"cm0102.exe" not in setup or b"cm0102_GDI.exe" not in setup:
        raise ValueError("inner updater metadata does not match the expected release")
    differences = sum(a != b for a, b in zip(normal, current)) + abs(len(normal)-len(current))
    result = {
        "comparison_date": "2026-10-18",
        "source": {"repository": "https://github.com/cm0102-linux/cm0102-linux", "commit": COMMIT, "url": URL,
                   "source_kind": "community mirror of official updater; publisher-hosted copy unavailable"},
        "installer": {"bytes": len(installer), "sha256": digest(installer), "zip_members": members},
        "update_payload": {"bytes": len(update), "sha256": digest(update), "zip_crc_verified": True,
                           "length_table_offset": 0, "length_table_bytes": header_bytes,
                           "full_partition_verified": True, "entries": positions},
        "patch_executable": {"name": "cm0102.exe", "payload_offset": header_bytes, "bytes": len(normal), "sha256": digest(normal)},
        "gdi_executable": {"name": "cm0102_GDI.exe", "payload_offset": gdi_offset, "bytes": len(gdi), "sha256": digest(gdi)},
        "current_specimen": {"bytes": len(current), "sha256": digest(current)},
        "byte_identical": normal == current,
        "differing_bytes_including_unpaired_bytes": differences,
        "executed_any_target_code": False,
        "limitations": ["No publisher-hosted artifact or publisher-issued cryptographic digest was available to authenticate the historical mirror",
                        "Equality proves equivalence to the executable in this archived updater, not independent publisher authentication",
                        "This is an on-disk comparison; loader and other runtime patches were not applied or tested"]
    }
    return result, normal, gdi

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current_executable", type=Path)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--installer", type=Path, help="use an already-downloaded copy of the pinned updater")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a fresh directory")
    if args.installer:
        installer = args.installer.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=120) as response:
            installer = response.read()
    result, normal, gdi = compare(installer, args.current_executable.read_bytes())
    args.output.mkdir(parents=True)
    (args.output/"comparison.json").write_text(json.dumps(result, indent=2)+"\n")
    (args.output/"cm0102.exe").write_bytes(normal)
    (args.output/"cm0102_GDI.exe").write_bytes(gdi)
    print(json.dumps({key: result[key] for key in ["byte_identical", "differing_bytes_including_unpaired_bytes", "patch_executable"]}, indent=2))

if __name__ == "__main__":
    main()
