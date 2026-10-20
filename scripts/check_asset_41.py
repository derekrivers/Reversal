"""Synthetic parser/conversion regressions; no installed game files required."""
import json
import struct
import zlib

from inventory_asset_41 import pe_resources, require, rgn_info, rgn_png


def rejected(call):
    try:
        call()
    except ValueError:
        return
    raise RuntimeError("malformed input accepted")


def synthetic_pe():
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x14c, 1)
    struct.pack_into("<H", data, 0x94, 224)
    struct.pack_into("<H", data, 0x98, 0x10b)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    struct.pack_into("<II", data, 0x98 + 112, 0x1000, 0x100)
    struct.pack_into("<IIII", data, 0x98 + 224 + 8, 0x400, 0x1000, 0x400, 0x200)
    for relative, resource_id, child in [(0, 2, 0x80000020), (0x20, 42, 0x80000040), (0x40, 1033, 0x60)]:
        struct.pack_into("<HH", data, 0x200 + relative + 12, 0, 1)
        struct.pack_into("<II", data, 0x200 + relative + 16, resource_id, child)
    struct.pack_into("<IIII", data, 0x260, 0x1100, 40, 0, 0)
    struct.pack_into("<IiiHH", data, 0x300, 40, 3, 5, 1, 8)
    return data


def main():
    # Six canonical RGB565 colors verify channel placement and row orientation.
    header = struct.pack("<12I", 3, 2, 12, 0, 32, 64, 0, 16, 0xf800, 0x7e0, 0x1f, 0)
    rgn = header + struct.pack("<6H", 0xf800, 0x7e0, 0x1f, 0xffff, 0, 0xffe0)
    require(rgn_info(rgn)["width"] == 3, "RGN width")
    png = rgn_png(rgn)
    at, raw, kinds = 8, b"", []
    while at < len(png):
        length = struct.unpack(">I", png[at:at + 4])[0]
        kind, payload = png[at + 4:at + 8], png[at + 8:at + 8 + length]
        require(struct.unpack(">I", png[at + 8 + length:at + 12 + length])[0] == zlib.crc32(kind + payload), "PNG CRC")
        if kind == b"IDAT":
            raw += payload
        kinds.append(kind)
        at += length + 12
    require(kinds == [b"IHDR", b"IDAT", b"IEND"], "PNG chunks")
    require(zlib.decompress(raw) == bytes([0,255,0,0,0,255,0,0,0,255,0,255,255,255,0,0,0,255,255,0]), "PNG pixels/row order")
    rejected(lambda: rgn_info(rgn[:-1]))
    rejected(lambda: rgn_info(rgn + b"x"))
    wrong = bytearray(rgn)
    struct.pack_into("<I", wrong, 32, 0x7c00)
    rejected(lambda: rgn_info(wrong))
    wrong = bytearray(rgn)
    struct.pack_into("<I", wrong, 0, 0xffffffff)
    rejected(lambda: rgn_info(wrong))
    pe = synthetic_pe()
    resources = pe_resources(pe)
    require(len(resources) == 1 and resources[0]["resource_path"] == [2, 42, 1033], "PE leaf identity")
    require(resources[0]["width"] == 3 and resources[0]["height"] == 5 and resources[0]["bits_per_pixel"] == 8, "DIB metadata")
    for offset, value in [(0x214, 0x80000000), (0x214, 0x80000100), (0x260, 0x2000), (0x264, 0xffffffff)]:
        wrong = bytearray(pe)
        struct.pack_into("<I", wrong, offset, value)
        rejected(lambda: pe_resources(wrong))
    print(json.dumps({"synthetic_rgb565_png": "pass", "pe_resource_metadata": "pass", "malformed_input_rejections": 8}))


if __name__ == "__main__":
    main()
