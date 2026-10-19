#!/usr/bin/env python3
"""Require the exact bounded synthetic R28-B evidence schema and schedule."""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re


PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
SITE_SHA256 = "a89054f25cd4c6ca54ad10b5d3c193a25b41fc858b56d32048a3d3209617c2a5"
ORACLE_SHA256 = "b8b7bd2c391875b67acb74477ae4632674d3a84a5bb16a7a9e7aa75fba183457"
ORACLE_GZIP_HEADER = bytes.fromhex("1f8b08000000000002ff")
OFFSETS = (0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 63, 127, 255, 511, 0x7f0)
TRACE = ("0068d020", "0068d022", "0068d024", "0068d027", "0068d02a", "0068d02d", "0068d030")
REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")
ROW_FIELDS = {"input", "initial", "final", "trace", "events", "memory_sha256"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact_int(actual, expected, label):
    if type(actual) is not int or actual != expected:
        raise ValueError(label)


def validate(sites_raw, oracle):
    if sha(sites_raw) != SITE_SHA256:
        raise ValueError("site evidence hash mismatch")
    sites = json.loads(sites_raw)
    if set(sites) != {"work_unit", "specimen_sha256", "checkpoint_archive_sha256",
                      "export_manifest_sha256", "preflight_sha256", "method", "functions"}:
        raise ValueError("unexpected site evidence fields")
    if sites["work_unit"] != "R28-B" or sites["specimen_sha256"] != PINNED:
        raise ValueError("site provenance mismatch")
    if set(oracle) != {"work_unit", "specimen_sha256", "sites_sha256", "domain",
                       "cases_count", "executed_instruction_steps", "covered_instruction_starts",
                       "covered_edges", "cases"}:
        raise ValueError("unexpected oracle fields")
    if oracle["work_unit"] != "R28-B" or oracle["specimen_sha256"] != PINNED or \
            oracle["sites_sha256"] != SITE_SHA256 or \
            oracle["domain"] != "256 synthetic mapped, stable receiver/stack inputs; original entry to RET":
        raise ValueError("oracle provenance/domain mismatch")
    exact_int(oracle["cases_count"], 256, "case count mismatch")
    exact_int(oracle["executed_instruction_steps"], 1792, "step count mismatch")
    if oracle["covered_instruction_starts"] != list(TRACE) or \
            oracle["covered_edges"] != [[a, b] for a, b in zip(TRACE, TRACE[1:])]:
        raise ValueError("oracle instruction/CFG coverage mismatch")
    if type(oracle["cases"]) is not list or len(oracle["cases"]) != 256:
        raise ValueError("oracle row count mismatch")
    for index, row in enumerate(oracle["cases"]):
        if type(row) is not dict or set(row) != ROW_FIELDS:
            raise ValueError(f"unexpected oracle row fields {index}")
        seed, position = divmod(index, 16)
        offset = OFFSETS[position]
        receiver = 0x200100 + offset
        expected_input = {"seed": seed, "offset": offset, "receiver": receiver}
        if type(row["input"]) is not dict or set(row["input"]) != set(expected_input):
            raise ValueError(f"synthetic input schema mismatch {index}")
        for name, value in expected_input.items():
            exact_int(row["input"][name], value, f"synthetic input mismatch {index}:{name}")
        initial = {"eax": (0xdeadbeef + seed * 0x10101 + offset) & 0xffffffff,
                   "ebx": 0x87654321 ^ seed, "ecx": receiver, "edx": 0x12345678 ^ offset,
                   "esi": 0x01020304 ^ seed, "edi": 0xfeedface ^ offset,
                   "ebp": 0xcafef00d ^ seed, "esp": 0x400800, "eip": 0x68d020}
        final = {**initial, "eax": receiver, "ecx": 0, "esp": 0x400804, "eip": 0x700000}
        for name, expected in (("initial", initial), ("final", final)):
            registers = row[name]
            if type(registers) is not dict or set(registers) != set(REGISTERS):
                raise ValueError(f"{name} register schema mismatch {index}")
            for register, value in expected.items():
                exact_int(registers[register], value, f"{name} register mismatch {index}:{register}")
        if type(row["trace"]) is not list or row["trace"] != list(TRACE):
            raise ValueError(f"original instruction trace mismatch {index}")
        expected_events = [["write", f"{receiver+2:08x}", 4, 0],
                           ["write", f"{receiver+6:08x}", 4, 0],
                           ["write", f"{receiver+10:08x}", 4, 0],
                           ["write", f"{receiver:08x}", 2, 0],
                           ["read", "00400800", 4]]
        if type(row["events"]) is not list or row["events"] != expected_events:
            raise ValueError(f"synthetic ordered effect mismatch {index}")
        data = bytearray((i * 29 + seed * 17 + 3) & 255 for i in range(0x1000))
        stack = bytearray((i * 19 + seed * 11 + 5) & 255 for i in range(0x1000))
        stack[0x800:0x804] = (0x700000).to_bytes(4, "little")
        data[0x100+offset:0x100+offset+14] = bytes(14)
        digests = row["memory_sha256"]
        if type(digests) is not list or len(digests) != 2 or \
                any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in digests):
            raise ValueError(f"memory digest schema mismatch {index}")
        if digests != [sha(data), sha(stack)]:
            raise ValueError(f"synthetic full-memory digest mismatch {index}")


def parse_canonical(compressed):
    if len(compressed) > 250000:
        raise ValueError("unexpected compressed oracle size")
    decompressed = gzip.decompress(compressed)
    if len(decompressed) > 250000:
        raise ValueError("unexpected expanded oracle size")
    oracle = json.loads(decompressed)
    canonical_json = (json.dumps(oracle, separators=(",", ":")) + "\n").encode()
    if decompressed != canonical_json:
        raise ValueError("noncanonical compact JSON serialization")
    # Python 3.12 may generate OS=0x03 with mtime=0; 3.13 generates 0xff.
    # Check the retained FF envelope directly instead of recompressing it.
    if compressed[:10] != ORACLE_GZIP_HEADER or sha(compressed) != ORACLE_SHA256:
        raise ValueError("noncanonical retained gzip envelope")
    return oracle


def check(sites_path, oracle_path):
    sites_raw = sites_path.read_bytes()
    compressed = oracle_path.read_bytes()
    oracle = parse_canonical(compressed)
    validate(sites_raw, oracle)
    mutations = []
    for label, mutate in (
        ("raw page in initial register", lambda row: row["initial"].update(raw_page="00" * 4096)),
        ("raw page in final register", lambda row: row["final"].update(eax="00" * 4096)),
        ("wrong synthetic offset", lambda row: row["input"].update(offset=0x100)),
        ("raw page in ordered event", lambda row: row["events"].append(["page", "00" * 4096])),
        ("raw page in memory digest", lambda row: row["memory_sha256"].__setitem__(0, "00" * 4096)),
        ("wrong 64-hex memory digest", lambda row: row["memory_sha256"].__setitem__(0, "0" * 64)),
    ):
        changed = copy.deepcopy(oracle)
        mutate(changed["cases"][0])
        try:
            validate(sites_raw, changed)
        except ValueError:
            mutations.append(label + " rejected")
        else:
            raise ValueError("privacy mutation admitted: " + label)
    expanded = gzip.decompress(compressed)
    os3_payload = bytearray(compressed)
    os3_payload[9] = 0x03
    if compressed[9] != 0xff or gzip.decompress(os3_payload) != expanded:
        raise ValueError("gzip OS-byte variant regression setup failed")
    if parse_canonical(compressed) != oracle:
        raise ValueError("retained OS=0xff gzip variant rejected")
    header_payload = bytearray(compressed)
    header_payload[3] |= 0x08  # FNAME: valid optional gzip header field.
    header_payload = header_payload[:10] + b"hidden-name\0" + header_payload[10:]
    for label, changed in (
        ("appended JSON whitespace", gzip.compress(expanded + b" ", mtime=0)),
        ("embedded JSON tab", gzip.compress(expanded.replace(b'{"work_unit"', b'{\t"work_unit"', 1), mtime=0)),
        ("Python 3.12 OS=0x03 header variant", bytes(os3_payload)),
        ("optional gzip header payload", bytes(header_payload)),
    ):
        try:
            parse_canonical(changed)
        except ValueError:
            mutations.append(label + " rejected")
        else:
            raise ValueError("privacy envelope mutation admitted: " + label)
    return {"work_unit": "R28-B", "status": "passed", "synthetic_cases": 256,
            "retained_memory": "two verified SHA-256 digests per case; no memory pages or PE bytes",
            "oracle_compressed_bytes": len(compressed), "negative_mutations": mutations}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sites", "oracle", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(check(args.sites, args.oracle), indent=2) + "\n",
                           encoding="utf-8", newline="\n")
