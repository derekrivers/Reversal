"""Verify the complete R22-B local x86 body against a read-only native export.

The output contains bounded site metadata, never executable bytes or pseudocode.
All integrity checks are explicit and remain active with python -O.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SPECIMEN_SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "2001cb0b2f047ddd573fd17ae5c0e89ebefa24f4f224a8bcf4bb023c04cc61dc"
PREFLIGHT_SHA = "03c82ef51e320c9483697b2446ad4421da7e96bd0068532d88f4a26cd5753560"
START, LENGTH = 0x6CEB90, 2899
TABLE, TABLE_COUNT = 0x6CF6E4, 8
NORETURN_SITES = {0x6CF66A, 0x6CF6DE}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(number):
    return f"{number:08x}"


def normalized(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = re.sub(r"st\((\d)\)", r"st\1", text)
    text = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16) + 0x80000000) % 0x100000000 - 0x80000000), text)
    text = re.sub(r"\s+", "", text).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    if text == "fsubpst1":
        text = "fsubp"
    for old, new in (("jnz", "jne"), ("jz", "je"), ("setnz", "setne"), ("setz", "sete")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


def run(args):
    raw = args.binary.read_bytes()
    need(len(raw) == 7192576 and sha(raw) == SPECIMEN_SHA, "specimen size/SHA-256 mismatch")
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    manifest_raw = (args.exports / "manifest.json").read_bytes()
    preflight_raw = args.preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST_SHA, "export manifest SHA-256 mismatch")
    need(sha(preflight_raw) == PREFLIGHT_SHA, "annotation preflight SHA-256 mismatch")
    manifest, preflight = json.loads(manifest_raw), json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == preflight["sha256"] == SPECIMEN_SHA, "input specimen metadata mismatch")
    need(manifest["preflight_sha256"] == PREFLIGHT_SHA and
         manifest["checkpoint_archive_sha256"] == "bf4e1739d0c1ab1780fca5f95ec9bf0f9447d7cbe28520366a79aa36b6cc5971",
         "native checkpoint metadata mismatch")
    need(set(manifest["files"]) == {"006ceb90.asm", "006ceb90.c"}, "unexpected export files")
    for name, meta in manifest["files"].items():
        payload = (args.exports / name).read_bytes()
        need(len(payload) == meta["bytes"] and sha(payload) == meta["sha256"], "export size/SHA-256 mismatch: " + name)
    need(preflight["sites"] == [{"address": "006ceb90", "function_name": "FUN_006ceb90",
                                  "function_comment_blank": True, "instruction_exists": True,
                                  "body_addresses": LENGTH}], "exact-old native preflight mismatch")

    need(raw[:2] == b"MZ", "MZ header missing")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    need(raw[pe:pe + 4] == b"PE\0\0" and struct.unpack_from("<H", raw, pe + 4)[0] == 0x14C,
         "expected x86 PE")
    count, opt_size = struct.unpack_from("<H", raw, pe + 6)[0], struct.unpack_from("<H", raw, pe + 20)[0]
    optional = pe + 24
    need(struct.unpack_from("<H", raw, optional)[0] == 0x10B, "expected PE32")
    base = struct.unpack_from("<I", raw, optional + 28)[0]
    sections = [struct.unpack_from("<IIII", raw, optional + opt_size + 40 * n + 8)[1:] for n in range(count)]

    def file_offset(va, size):
        for rva, length, offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= length:
                return offset + delta
        raise ValueError("virtual range is not raw-section-backed: " + hx(va))

    def read_va(va, size):
        off = file_offset(va, size)
        return raw[off:off + size]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    rows = list(md.disasm(read_va(START, LENGTH), START))
    need(sum(i.size for i in rows) == LENGTH, "incomplete contiguous original-body decode")
    need(rows[0].address == START and rows[-1].address + rows[-1].size == START + LENGTH,
         "decoded body endpoint mismatch")
    native_text = (args.exports / "006ceb90.asm").read_text(encoding="utf-8-sig")
    native = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", native_text, re.M)]
    need(len(native) == len(rows), "native/original instruction-count mismatch")
    for instruction, (address, description) in zip(rows, native):
        need(instruction.address == address and
             normalized(description) == normalized(instruction.mnemonic + " " + instruction.op_str),
             "native/original address, mnemonic or operand mismatch at " + hx(instruction.address) +
             " native=" + normalized(description) +
             " original=" + normalized(instruction.mnemonic + " " + instruction.op_str))

    instructions = {i.address: i for i in rows}
    case_targets = [struct.unpack_from("<I", read_va(TABLE + 4 * n, 4))[0] for n in range(TABLE_COUNT)]
    need(case_targets == [0x6CED17, 0x6CED39, 0x6CED5B, 0x6CEFCA,
                          0x6CF00D, 0x6CF1F4, 0x6CF1F4, 0x6CF58A],
         "switch-table target mismatch")
    need(TABLE not in instructions and all(t in instructions for t in case_targets),
         "switch table must be outside local code body and target only local instructions")
    indirect = [i for i in rows if i.mnemonic == "jmp" and i.operands[0].type != CS_OP_IMM]
    need(len(indirect) == 1 and indirect[0].address == 0x6CED10 and
         indirect[0].op_str == "dword ptr [eax*4 + 0x6cf6e4]", "unexpected indirect branch")

    def successors(i):
        if i.mnemonic == "ret" or i.address in NORETURN_SITES:
            return []
        if i.address == 0x6CED10:
            return list(dict.fromkeys(case_targets))
        next_address = i.address + i.size
        if i.mnemonic.startswith("j"):
            need(i.operands[0].type == CS_OP_IMM, "unhandled indirect branch")
            return [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else [next_address])
        return [next_address]

    edges = {i.address: successors(i) for i in rows}
    for origin, targets in edges.items():
        need(all(t in instructions for t in targets), "out-of-body local edge at " + hx(origin))
    reached, todo = set(), [START]
    while todo:
        at = todo.pop()
        if at not in reached:
            reached.add(at)
            todo.extend(edges[at])
    need(reached == set(instructions), "native exported instructions are not all structurally reachable")

    branches = [[hx(i.address), i.mnemonic, [hx(t) for t in edges[i.address]]]
                for i in rows if i.mnemonic.startswith("j")]
    calls_by_target = defaultdict(list)
    for i in rows:
        if i.mnemonic == "call":
            need(i.operands[0].type == CS_OP_IMM, "unexpected indirect call")
            calls_by_target[hx(i.operands[0].imm)].append(hx(i.address))
    rng_sites = {int(site, 16) for site in calls_by_target.get("0090cfc0", [])}
    need(rng_sites == {0x6CEEDC, 0x6CEF38, 0x6CF19B}, "direct RNG site set changed")
    # Stop at the one candidate-loop latch: a different iteration may draw again.
    for first in rng_sites:
        pending, visited = list(edges[first]), set()
        while pending:
            site = pending.pop()
            if site == 0x6CF5C3 or site in visited:
                continue
            need(site not in rng_sites, "two direct RNG sites can occur in one candidate iteration")
            visited.add(site)
            pending.extend(edges[site])
    memory_reads, memory_writes, x87 = [], [], []
    for i in rows:
        if i.mnemonic.startswith("f"):
            x87.append([hx(i.address), i.mnemonic])
        for o in i.operands:
            if o.type != CS_OP_MEM or i.mnemonic == "lea":
                continue
            descriptor = [hx(i.address), i.mnemonic, o.size, i.op_str]
            access = o.access
            if i.mnemonic in ("fst", "fstp", "fistp"):
                access = capstone.CS_AC_WRITE
            if access & capstone.CS_AC_READ:
                memory_reads.append(descriptor)
            if access & capstone.CS_AC_WRITE:
                memory_writes.append(descriptor)
    nonframe_writes = [s for s in memory_writes if "[esp" not in s[3]]
    # These are local write *sites*, not an execution count or a transitive effect census.
    need([i.address for i in rows if i.mnemonic == "ret"] == [0x6CF5F8] and
         rows[-1].address == 0x6CF6DE, "return/cold-tail boundaries changed")
    need(len(rows) == 832 and len(calls_by_target) == 15 and
         sum(map(len, calls_by_target.values())) == 47,
         "instruction or call census changed")
    return {
        "work_unit": "R22-B", "evidence_class": "complete local static instruction mapping; no execution oracle",
        "specimen_sha256": SPECIMEN_SHA, "checkpoint_archive_sha256": manifest["checkpoint_archive_sha256"],
        "export_manifest_sha256": MANIFEST_SHA, "annotation_preflight_sha256": PREFLIGHT_SHA,
        "decoder": "Capstone 5.0.7 x86-32", "python_optimized_integrity": "explicit ValueError gates; no assert",
        "entry_va": hx(START), "body_bytes": LENGTH, "body_end_exclusive_va": hx(START + LENGTH),
        "body_file_offset": f"0x{file_offset(START, LENGTH):x}", "body_sha256": sha(read_va(START, LENGTH)),
        "instruction_count": len(rows), "all_original_and_native_instructions_match": True,
        "all_instructions_structurally_reachable": True,
        "branch_sites": branches, "branch_count": len(branches),
        "switch": {"site_va": "006ced10", "index_checked_at_va": "006ced07",
                   "table_va": hx(TABLE), "table_file_offset": f"0x{file_offset(TABLE, TABLE_COUNT * 4):x}",
                   "table_sha256": sha(read_va(TABLE, TABLE_COUNT * 4)),
                   "case_targets_va": [hx(t) for t in case_targets],
                   "out_of_range_default_va": "006cf5fb"},
        "direct_calls": [{"target_va": target, "sites_va": sites} for target, sites in sorted(calls_by_target.items())],
        "direct_call_site_count": sum(map(len, calls_by_target.values())),
        "direct_rng_sites_va": calls_by_target.get("0090cfc0", []),
        "direct_rng_sites_mutually_exclusive_per_candidate_iteration": True,
        "direct_x87_conversion_sites_va": calls_by_target.get("00945640", []),
        "returns": [{"site_va": "006cf5f8", "callee_cleanup_bytes": 12}],
        "local_noreturn_call_sites_va": [hx(n) for n in sorted(NORETURN_SITES)],
        "explicit_memory_reads": memory_reads, "explicit_memory_writes": memory_writes,
        "nonframe_write_sites": nonframe_writes, "x87_sites": x87,
        "limits": ["Raw local sites only; callee writes, RNG and failures are excluded",
                   "Switch table is pinned PE data outside the 2899-byte code body",
                   "Structural reachability does not prove input feasibility",
                   "No live pointer, alias, x87 numerical or connected selection equivalence"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-selection-22-sites.json"))
    parsed = parser.parse_args()
    result = run(parsed)  # Verify every input before opening the output.
    parsed.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("wrote " + str(parsed.output) + "; complete local static mapping only")
