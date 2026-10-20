"""Offline resource metadata and strict RGB565 RGN conversion; no game/process access.

Originals, private alias manifests and converted images belong outside Git. The
public manifest contains hashes and opaque aliases only, never original bytes.
Python standard library only. No integrity checks depend on assert / __debug__.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import wave
import zlib
from collections import Counter


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded(data, offset, length):
    require(offset >= 0 and length >= 0 and offset + length <= len(data), "out-of-file region")
    return data[offset:offset + length]


def rgn_info(data):
    fields = struct.unpack("<12I", bounded(data, 0, 48))
    width, height, size = fields[:3]
    require(0 < width <= 8192 and 0 < height <= 8192, "unsupported RGN dimensions")
    require(size == width * height * 2 and len(data) == 48 + size, "RGN payload size mismatch")
    require(fields[7:] == (16, 0xf800, 0x7e0, 0x1f, 0), "unsupported RGN masks/depth")
    return {"format": "RGN RGB565 candidate", "width": width, "height": height,
            "payload_offset": 48, "bits_per_pixel": 16, "masks": [0xf800, 0x7e0, 0x1f],
            "palette": None, "transparency": "no alpha mask; runtime color-key unknown",
            "orientation": "file row order; top-down supported by representative visual inspection"}


def rgn_png(data):
    info = rgn_info(data)
    width, height = info["width"], info["height"]
    pixels = bounded(data, 48, width * height * 2)
    rows = bytearray()
    for y in range(height):
        rows.append(0)  # PNG filter None
        for (pixel,) in struct.iter_unpack("<H", pixels[y * width * 2:(y + 1) * width * 2]):
            r, g, b = (pixel >> 11) & 31, (pixel >> 5) & 63, pixel & 31
            rows.extend(((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2)))
    def chunk(kind, payload):
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b""))


def pe_resources(data):
    """Walk disk PE32 resource leaves. Resource directory offsets stay root-relative."""
    require(bounded(data, 0, 2) == b"MZ", "missing DOS signature")
    pe = struct.unpack("<I", bounded(data, 0x3c, 4))[0]
    require(bounded(data, pe, 4) == b"PE\0\0", "missing PE signature")
    machine, count = struct.unpack("<HH", bounded(data, pe + 4, 4))
    optsize = struct.unpack("<H", bounded(data, pe + 20, 2))[0]
    opt = pe + 24
    require(machine == 0x14c and struct.unpack("<H", bounded(data, opt, 2))[0] == 0x10b, "requires x86 PE32")
    require(optsize >= 120 and struct.unpack("<I", bounded(data, opt + 92, 4))[0] >= 3, "missing resource directory slot")
    rva, size = struct.unpack("<II", bounded(data, opt + 112, 8))
    sections = []
    for i in range(count):
        at = opt + optsize + i * 40
        virtual_size, virtual, raw_size, raw = struct.unpack("<IIII", bounded(data, at + 8, 16))
        sections.append((virtual, raw_size, raw))
    def offset(address, length):
        choices = [raw + address - virtual for virtual, raw_size, raw in sections
                   if virtual <= address and address + length <= virtual + raw_size]
        require(len(choices) == 1, "unmapped/ambiguous resource RVA")
        bounded(data, choices[0], length)
        return choices[0]
    if not rva and not size:
        return []
    base = offset(rva, size)
    def region(relative, length):
        require(relative >= 0 and relative + length <= size, "resource directory region outside declared size")
        return bounded(data, base + relative, length)
    leaves, visited = [], set()
    def walk(relative, path):
        require(len(path) <= 3 and relative not in visited, "resource cycle/depth")
        visited.add(relative)
        named, ids = struct.unpack("<HH", region(relative + 12, 4))
        require(named + ids <= 4096, "excessive resource entries")
        for i in range(named + ids):
            name, child = struct.unpack("<II", region(relative + 16 + i * 8, 8))
            # String names are hashed; public metadata never copies arbitrary resource strings.
            if name & 0x80000000:
                at = name & 0x7fffffff
                length = struct.unpack("<H", region(at, 2))[0]
                label = "name-sha256:" + digest(region(at + 2, length * 2))
            else:
                label = name
            if child & 0x80000000:
                walk(child & 0x7fffffff, path + [label])
            else:
                address, length, codepage, reserved = struct.unpack("<IIII", region(child, 16))
                payload = bounded(data, offset(address, length), length)
                leaf = {"resource_path": path + [label], "size": length, "sha256": digest(payload), "codepage": codepage}
                if path and path[0] == 2 and len(payload) >= 40 and struct.unpack("<I", payload[:4])[0] == 40:
                    width, height, planes, bpp = struct.unpack("<iiHH", payload[4:16])
                    leaf.update(format="DIB", width=width, height=height, bits_per_pixel=bpp)
                elif path and path[0] in (1, 3):
                    dib = 4 if path[0] == 1 else 0
                    if len(payload) >= dib + 40 and struct.unpack("<I", payload[dib:dib + 4])[0] == 40:
                        width, combined_height, planes, bpp = struct.unpack("<iiHH", payload[dib + 4:dib + 16])
                        require(combined_height % 2 == 0, "odd icon combined image/mask height")
                        leaf.update(format="cursor DIB" if dib else "icon DIB", width=width,
                                    height=combined_height // 2, bits_per_pixel=bpp,
                                    transparency="AND mask; no runtime alpha claim")
                leaves.append(leaf)
    walk(0, [])
    return leaves


RESOURCE_EXTENSIONS = {".rgn", ".fnt", ".ttf", ".wav", ".exe", ".dll", ".pct"}
IDENTITY_EXTENSIONS = {".dat", ".lng", ".cfg"}


def inventory(root):
    require(root.is_dir(), "installation root is not a directory")
    public, aliases, groups = [], {}, {}
    paths = sorted((p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in RESOURCE_EXTENSIONS | IDENTITY_EXTENSIONS),
                   key=lambda p: p.relative_to(root).as_posix().casefold())
    require(bool(paths), "no supported resource/configuration files found")
    for path in paths:
        relative = path.relative_to(root).as_posix()
        alias = "source-" + digest(relative.encode("utf-8"))[:16]
        require(alias not in aliases, "source alias collision")
        aliases[alias] = relative
        data = path.read_bytes()
        sha = digest(data)
        if sha in groups:
            groups[sha]["source_aliases"].append(alias)
            continue
        ext = path.suffix.lower()
        row = {"asset_id": "asset-sha256-" + sha, "sha256": sha, "size": len(data), "extension": ext,
               "source_aliases": [alias], "format": "unresolved", "observed_use": "unknown",
               "rights": "original/modded installed content; redistribution permission not established",
               "react_availability": "local-only; no asset bytes in public build"}
        if ext == ".rgn":
            row.update(rgn_info(data))
        elif ext == ".wav":
            with wave.open(str(path), "rb") as wav:
                row.update(format="RIFF WAVE PCM", channels=wav.getnchannels(), sample_rate=wav.getframerate(),
                           sample_width_bytes=wav.getsampwidth(), frames=wav.getnframes())
        elif ext in {".exe", ".dll"}:
            try:
                row.update(format="PE32 x86", resources=pe_resources(data))
            except ValueError as error:
                row.update(format="unresolved executable container", resource_parse_error=str(error))
        elif ext == ".ttf":
            row.update(format="sfnt TrueType", font_metrics="unparsed")
        elif ext == ".fnt":
            row.update(format="game font container; not Windows FNT signature", glyph_metrics="unresolved")
        elif ext == ".pct":
            row.update(format="tactical container candidate; not an identified picture format")
        elif ext in IDENTITY_EXTENSIONS:
            row.update(format="configuration/database identity only; contents not exported")
        public.append(row)
        groups[sha] = row
    return {"schema": "reversal.asset-inventory-41.v1", "scope": "offline installation resource and data/config identities; saves excluded",
            "source_count": len(paths), "unique_content_count": len(public),
            "source_extensions": dict(sorted(Counter(p.suffix.lower() for p in paths).items())), "assets": public}, aliases


def exclusive_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    inv = commands.add_parser("inventory")
    inv.add_argument("root", type=Path)
    inv.add_argument("--public-output", required=True, type=Path)
    inv.add_argument("--private-alias-output", required=True, type=Path)
    convert = commands.add_parser("convert-rgn")
    convert.add_argument("source", type=Path)
    convert.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.mode == "inventory":
        result, aliases = inventory(args.root)
        # Alias data is private. Neither output is permitted to replace existing evidence.
        exclusive_json(args.private_alias_output, {"schema": "reversal.asset-aliases-41.private.v1", "aliases": aliases})
        exclusive_json(args.public_output, result)
        print(json.dumps({"source_count": result["source_count"], "unique_content_count": result["unique_content_count"]}))
    else:
        data = args.source.read_bytes()
        png = rgn_png(data)
        with args.output.open("xb") as handle:
            handle.write(png)
        print(json.dumps({"source_sha256": digest(data), "output_sha256": digest(png), **rgn_info(data)}))


if __name__ == "__main__":
    main()
