#!/usr/bin/env python3
"""Pin four exact receiver-cleanup body shapes to the original PE instructions."""
from __future__ import annotations

# Integrity assertions below are required before any evidence can be produced.
if not __debug__:
    raise SystemExit("extract_cleanup_family_18 refuses optimized Python; integrity assertions are required")

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
EXPORT_MANIFEST = "e5df99ec062265fe66277a9d1dc09887472fea081132a51471e54b6e49614393"
SEMANTIC_COMMIT = "a2a2b8de126d3d8a555c3eb7c8ea777b07a269ec"
# Historical overlay used by the original census, supplied separately from the
# evolving current registry. Its digest is checked before parsing below.
SEMANTIC_SHA256 = "dcb2596fde871086ee984e3765ff6a5d726ff23121128c6a0882dbf3c1ca80a1"
TEMPLATES = {"A201": ("00410840", 201, 52),
             "B191": ("00401220", 191, 43),
             "C135": ("0041df80", 135, 28),
             "D180": ("0042f510", 180, 20)}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_reader(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe + 4)[0] == 0x14c
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    assert struct.unpack_from("<H", data, opt)[0] == 0x10b
    base = struct.unpack_from("<I", data, opt + 28)[0]
    sections = [struct.unpack_from("<IIII", data, opt + opt_size + 40 * i + 8)
                for i in range(count)]

    def read(va: int, length: int) -> bytes:
        rva = va - base
        for _vsize, start, size, raw in sections:
            if start <= rva and rva + length <= start + size:
                return data[raw + rva - start:raw + rva - start + length]
        raise ValueError(f"unmapped PE span {va:08x}+{length}")

    return read


def decode(md, read, entry: int, size: int):
    body = read(entry, size)
    ins = list(md.disasm(body, entry))
    if not ins or ins[0].address != entry or ins[-1].address + ins[-1].size != entry + size:
        return None
    if sum(i.size for i in ins) != size:
        return None
    return body, ins


def shape(ins, entry: int, size: int):
    starts = {i.address for i in ins}
    out = []
    for i in ins:
        rel = i.address - entry
        operand = i.op_str
        if rel == 2 and i.mnemonic == "push" and re.fullmatch(r"0x[0-9a-f]+", operand):
            value = int(operand, 16)
            if not 0x900000 <= value < 0x980000:
                return None
            operand = "<seh-metadata>"
        elif rel == 0x1e and i.mnemonic == "mov":
            m = re.fullmatch(r"dword ptr \[esi\], (0x[0-9a-f]+)", operand)
            if not m or not 0x900000 <= int(m[1], 16) < 0x980000:
                return None
            operand = "dword ptr [esi], <vtable-like-address>"
        elif i.mnemonic.startswith("j") and re.fullmatch(r"0x[0-9a-f]+", operand):
            target = int(operand, 16)
            if target not in starts:
                return None
            operand = f"<local+{target - entry:x}>"
        out.append((rel, i.mnemonic, operand))
    return tuple(out)


REGISTER_BITS = {name: bits for bits, names in (
    (32, "eax ebx ecx edx esi edi ebp esp"),
    (16, "ax bx cx dx si di bp sp"),
    (8, "al bl cl dl ah bh ch dh")) for name in names.split()}
SYNONYMS = {"jz": "je", "jnz": "jne", "jna": "jbe", "jnbe": "ja",
            "jnl": "jge", "jnge": "jl", "jng": "jle", "jnle": "jg"}


def normalize_instruction(mnemonic: str, operands: str):
    """Accept only spelling differences in this bounded x86 export vocabulary.

    Keep widths, registers, segments, immediates, displacements, scale factors,
    branch addresses and callees. No template literal/target masking belongs in
    the independent native-sample comparison. Unknown syntax fails closed.
    """
    mnemonic = SYNONYMS.get(mnemonic.lower(), mnemonic.lower())
    parts = [p.strip().lower() for p in operands.split(",")] if operands.strip() else []
    normalized = []
    for part in parts:
        if part in REGISTER_BITS:
            normalized.append(("register", REGISTER_BITS[part], part))
            continue
        if re.fullmatch(r"-?(?:0x[0-9a-f]+|[0-9]+)", part):
            normalized.append(("immediate", int(part, 16) if "0x" in part else int(part)))
            continue
        memory = re.fullmatch(r"(?:(byte|word|dword)\s+ptr\s+)?(?:(cs|ds|es|fs|gs|ss):)?\[([^\[\]]+)\]", part)
        if not memory:
            raise ValueError(f"unsupported native operand: {part!r}")
        width, segment, expression = memory.groups()
        if width is None:
            # Ghidra omits the width on MOV EAX,FS:[0]. MOV's peer register
            # independently fixes it; never infer from the expected PE operand.
            peers = [REGISTER_BITS[p] for p in parts if p in REGISTER_BITS]
            if mnemonic != "mov" or len(peers) != 1:
                raise ValueError(f"ambiguous native memory width: {part!r}")
            bits = peers[0]
        else:
            bits = {"byte": 8, "word": 16, "dword": 32}[width]
        compact = re.sub(r"\s+", "", expression)
        tokens = re.findall(r"0x[0-9a-f]+|[0-9]+|[a-z][a-z0-9]*|[+*\-]", compact)
        if not tokens or "".join(tokens) != compact:
            raise ValueError(f"unsupported native memory expression: {part!r}")
        canonical = []
        for token in tokens:
            if re.fullmatch(r"0x[0-9a-f]+|[0-9]+", token):
                canonical.append(int(token, 16) if token.startswith("0x") else int(token))
            elif token in REGISTER_BITS or token in ("+", "-", "*"):
                canonical.append(token)
            else:
                raise ValueError(f"unsupported native memory token: {token!r}")
        normalized.append(("memory", bits, segment, tuple(canonical)))
    return mnemonic, tuple(normalized)


def check_ghidra_sample(path: Path, ins):
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(ins), (path, len(lines), len(ins))
    for line, native in zip(lines, ins):
        m = re.fullmatch(r"([0-9A-Fa-f]{8})\s+([A-Za-z][A-Za-z0-9]*)\b\s*(.*)", line)
        assert m and int(m[1], 16) == native.address, (path, line)
        actual = normalize_instruction(m[2], m[3])
        expected = normalize_instruction(native.mnemonic, native.op_str)
        assert actual == expected, (path, f"native instruction mismatch at {native.address:08x}", actual, expected)


def main():
    ap = argparse.ArgumentParser()
    for arg in ("binary", "atlas", "exports", "semantic", "summary", "rows"):
        ap.add_argument(f"--{arg}", required=True, type=Path)
    args = ap.parse_args()
    data = args.binary.read_bytes()
    assert sha(data) == SPECIMEN
    read = pe_reader(data)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    atlas = [json.loads(line) for line in args.atlas.read_text(encoding="utf-8").splitlines()]
    assert len(atlas) == 9241
    by_entry = {r["entry"]: r for r in atlas}
    assert len(by_entry) == len(atlas)
    manifest_path = args.exports / "manifest.json"
    assert sha(manifest_path.read_bytes()) == EXPORT_MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["specimen_sha256"] == SPECIMEN
    for name, meta in manifest["files"].items():
        payload = (args.exports / name).read_bytes()
        assert len(payload) == meta["bytes"] and sha(payload) == meta["sha256"]

    references = {}
    for kind, (address, size, _count) in TEMPLATES.items():
        decoded = decode(md, read, int(address, 16), size)
        assert decoded is not None
        body, ins = decoded
        check_ghidra_sample(args.exports / f"{address}.asm", ins)
        references[kind] = shape(ins, int(address, 16), size)
        assert references[kind] is not None

    found = []
    candidates = Counter()
    for row in atlas:
        address = row["entry"]
        if row["name"].startswith("Unwind@"):
            continue
        size = row["body_bytes"]
        if size not in {x[1] for x in TEMPLATES.values()}:
            continue
        candidates[size] += 1
        entry = int(address, 16)
        if int(row["body_min"], 16) != entry or int(row["body_max"], 16) - entry + 1 != size:
            continue
        decoded = decode(md, read, entry, size)
        if decoded is None:
            continue
        body, ins = decoded
        normalized = shape(ins, entry, size)
        for kind, reference in references.items():
            if normalized != reference:
                continue
            calls = [i.op_str for i in ins if i.mnemonic == "call"]
            direct = sorted({f"{int(x, 16):08x}" for x in calls if re.fullmatch(r"0x[0-9a-f]+", x)})
            assert direct == sorted(x for x in row["direct_callees"] if not x.startswith("EXTERNAL:"))
            found.append({"entry": address, "template": kind, "body_bytes": size,
                          "instructions": len(ins), "body_sha256": sha(body),
                          "seh_metadata": f"{int(ins[1].op_str, 16):08x}",
                          "vtable_like_address": f"{int(ins[10].op_str.split(', ')[1], 16):08x}",
                          "direct_callees": direct,
                          "indirect_call_count": len(calls) - sum(x.startswith("0x") for x in calls)})
            break

    counts = Counter(r["template"] for r in found)
    assert counts == Counter({k: v[2] for k, v in TEMPLATES.items()}), counts
    assert len(found) == 143 and len({r["entry"] for r in found}) == len(found)
    found.sort(key=lambda r: r["entry"])
    evidence = args.atlas.parent.parent
    semantic_bytes = args.semantic.read_bytes()
    assert sha(semantic_bytes) == SEMANTIC_SHA256, f"expected historical overlay from {SEMANTIC_COMMIT}"
    semantic = {r["address"] for r in json.loads(semantic_bytes)["functions"]}
    current_semantic = {r["address"] for r in json.loads((evidence / "code-atlas/semantic-coverage.json").read_text(encoding="utf-8"))["functions"]}
    unwind = {json.loads(line)["entry"] for line in (evidence / "unwind-family-15-rows.jsonl").read_text(encoding="utf-8").splitlines()}
    wrappers = {json.loads(line)["entry"] for line in (evidence / "delete-wrapper-family-17-rows.jsonl").read_text(encoding="utf-8").splitlines()}
    family = {r["entry"] for r in found}
    assert len(semantic) == 79 and len(unwind) == 3873 and len(wrappers) == 192
    assert not family & (semantic | unwind | wrappers)
    assert not family & current_semantic
    assert not semantic & (unwind | wrappers) and not unwind & wrappers
    remaining = len(atlas) - len(family | semantic | unwind | wrappers)
    assert remaining == 4954
    summary = {"specimen_sha256": SPECIMEN, "atlas_functions": len(atlas),
               "scope": "exact original-instruction receiver-cleanup templates; mechanical local bodies, not full object or gameplay behavior",
               "total": len(found), "other_registry_unclassified": remaining,
               "templates": {k: {"sample": v[0], "body_bytes": v[1],
                                                   "members": counts[k], "instructions": len(references[k])}
                                              for k, v in TEMPLATES.items()},
               "candidate_sizes": dict(sorted(candidates.items())),
               "sample_manifest_sha256": EXPORT_MANIFEST,
               "native_sample_verification": {
                   "comparison": "complete normalized instructions including operand widths, registers, segments, immediates, memory expressions, branch targets and callees",
                   "samples": len(TEMPLATES), "instructions": sum(len(r) for r in references.values()),
                   "historical_semantic_commit": SEMANTIC_COMMIT,
                   "historical_semantic_sha256": SEMANTIC_SHA256,
                   "current_semantic_disjointness_checked": True,
                   "optimized_python": "refused before evidence I/O"},
               "limitations": ["Ghidra-inferred function starts and bounds", "call target effects unresolved",
                               "pointer literals and metadata identities not original C++ type declarations"]}
    args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    args.rows.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in found), encoding="utf-8", newline="\n")
    print(json.dumps({"total": len(found), "templates": dict(counts),
                      "summary_sha256": sha(args.summary.read_bytes()), "rows_sha256": sha(args.rows.read_bytes())}))


if __name__ == "__main__":
    main()
