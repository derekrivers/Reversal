"""Offline comparison of an A4 live lookup pair, fresh x86 replay and B2 TS."""
from __future__ import annotations
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys
import tempfile

import capstone
import check_engine_state_41b2 as b2
import replay_engine_state_41 as unit

SCHEMA = "reversal.engine-paired-return-41.result.v1"
RETURN = 0x6cf8f7


def require(ok, code):
    b2.demand(ok, "paired-return", code)


def region_bytes(region):
    require(isinstance(region, dict), "RETURN_REGION_SHAPE")
    address, size = region["address"], region["requested"]
    require(type(address) is int and type(size) is int and
            0 <= address < 2**32 and 0 < size <= 4096 and address + size <= 2**32,
            "RETURN_REGION_SHAPE")
    body = region["hex"]
    require(isinstance(body, str) and len(body) == size * 2 and
            re.fullmatch("[0-9a-fA-F]+", body) is not None, "RETURN_REGION_ENCODING")
    data = bytes.fromhex(body)
    require(region["complete"] is True and region["received"] == size and
            region["sha256"] == unit.sha(data), "RETURN_REGION_INTEGRITY")
    return data


def memory_map(regions):
    require(isinstance(regions, list) and len(regions) <= 128, "RETURN_REGION_BUDGET")
    memory, total = {}, 0
    for region in regions:
        data = region_bytes(region)
        total += len(data)
        require(total <= 65536, "RETURN_REGION_BUDGET")
        for offset, value in enumerate(data):
            address = region["address"] + offset
            require(address not in memory or memory[address] == value, "RETURN_ALIAS_CONFLICT")
            memory[address] = value
    return memory


def read(memory, address, size=4):
    require(all(address + k in memory for k in range(size)), "PAIR_MEMORY_MISSING")
    return int.from_bytes(bytes(memory[address + k] for k in range(size)), "little")


def registers(sample):
    regs = sample["registers"]
    require(isinstance(regs, dict) and all(
        type(regs.get(n)) is int and 0 <= regs[n] < 2**32
        for n in (*unit.REGS, "eflags")), "RETURN_REGISTER_SHAPE")
    return regs


def admit_pair(record):
    """Recompute identities and aliases; capture-tool booleans are checked too."""
    require(record.get("paired_return") is True and record.get("return_observed") is True and
            record.get("stop_reason") == "paired_return", "LIVE_RETURN_MISSING")
    require(record.get("return_runtime_va") == RETURN, "RETURN_ADDRESS")
    before, after = record["sample"], record["return_sample"]
    entry, returned = registers(before), registers(after)
    require(type(before["thread"]) is int and before["thread"] == after["thread"] and
            after["thread"] in record["restored_threads"], "RETURN_THREAD")
    require(entry["eip"] == 0x62e6e0 and returned["eip"] == RETURN, "RETURN_ADDRESS")
    require(entry["esp"] + 8 < 2**32 and returned["esp"] == entry["esp"] + 8, "RETURN_STACK")
    first_time, last_time = (datetime.fromisoformat(s["captured_utc"]) for s in (before, after))
    require(first_time.tzinfo is not None and last_time.tzinfo is not None and
            last_time > first_time, "PAIR_TIMESTAMP_ORDER")
    pairing = record["pairing"]
    require(all(pairing.get(n) is True for n in (
        "thread_matches", "caller_matches", "return_address_matches", "stack_matches_ret4")) and
        pairing["entry_esp"] == entry["esp"] and
        pairing["expected_return_esp"] == returned["esp"], "PAIR_METADATA")
    for name in ("ebx", "esi", "edi", "ebp"):
        require(returned[name] == entry[name], "RETURN_NONVOLATILE")
        require(pairing["nonvolatile_matches"].get(name) is True, "PAIR_METADATA")
    entry_regions = before["memory"] + before["lookup_closure"]["memory"]
    fixed = after["entry_regions_after"]
    require(isinstance(fixed, list) and len(fixed) == len(entry_regions), "FIXED_REREADS_MISSING")
    for original, current in zip(entry_regions, fixed):
        require(all(original.get(k) == current.get(k) for k in ("label", "address", "requested")),
                "FIXED_REREAD_IDENTITY")
        same = region_bytes(original) == region_bytes(current)
        require(current.get("unchanged") is same, "REREAD_EFFECT_METADATA")
    old = memory_map(entry_regions)
    require(isinstance(after["memory"], list) and len(after["memory"]) > 0, "RETURN_STACK_READ")
    new = memory_map(fixed + after["memory"])
    require(read(old, entry["esp"]) == RETURN, "PAIR_CALLER")
    require(after["memory"][0]["address"] == returned["esp"] and
            after["memory"][0]["requested"] == 512, "RETURN_STACK_READ")
    labels = {r["label"]: r for r in before["lookup_closure"]["memory"]}
    slot = labels["effect_esi_candidate_slot"]
    require(slot["address"] == entry["esi"] and slot["requested"] == 446, "SLOT_EXTENT")
    participant = read(old, entry["esp"] + 4)
    for memory in (old, new):
        require(read(memory, entry["esi"] + 0x69) == participant, "SLOT_STAFF_ALIAS")
        require(read(memory, entry["esi"] + 0x6d) == read(memory, participant + 0x61) != 0,
                "SLOT_ATTRIBUTE_ALIAS")
    closure = before["lookup_closure"]
    require(all(closure.get(key) is True for key in (
        "effect_return_address_matches", "slot_staff_pointer_matches", "slot_attribute_pointer_matches")),
        "SLOT_METADATA")
    # Scratch below the entry ESP belongs to the callee. It may change.
    # The fixed stack from ESP upward and all selected game-data bytes must agree.
    scratch_changed, stable_bytes = 0, 0
    for address, value in old.items():
        require(address in new, "FIXED_REREADS_MISSING")
        if entry["esp"] - 0x260 <= address < entry["esp"]:
            scratch_changed += value != new[address]
        else:
            require(new[address] == value, "SELECTED_STATE_CHANGED")
            stable_bytes += 1
    for sample in (before, after):
        fs = sample["fs"]
        require(fs.get("complete") is True and fs["head"]["address"] == fs["base"] and
                fs["head"]["requested"] == 4, "RETURN_FS_MISSING")
        region_bytes(fs["head"])
    require(before["fs"]["selector"] == after["fs"]["selector"] and
            before["fs"]["base"] == after["fs"]["base"] and
            region_bytes(before["fs"]["head"]) == region_bytes(after["fs"]["head"]), "RETURN_FS_CHANGED")
    # No x87/SSE operation exists on the admitted cached replay. Preserve the
    # entire captured areas as endpoint evidence, without publishing their bytes.
    for key in ("control_word", "status_word", "tag_word"):
        require(type(after["x87"][key]) is int and 0 <= after["x87"][key] <= 65535 and
                before["x87"][key] == after["x87"][key], "RETURN_X87_CHANGED")
    for key, size in (("legacy_register_area_hex", 80), ("extended_registers_hex", 512)):
        a = before["x87"][key] if key.startswith("legacy") else before[key]
        z = after["x87"][key] if key.startswith("legacy") else after[key]
        require(isinstance(a, str) and re.fullmatch("[0-9a-fA-F]{" + str(size * 2) + "}", a) is not None
                and a.lower() == z.lower(), "RETURN_FLOAT_AREA_CHANGED")
    return {"entry": entry, "returned": returned, "before": old, "after": new,
            "stable_bytes": stable_bytes, "scratch_changed": scratch_changed,
            "fixed_regions": len(fixed), "game_regions": len(labels) - 1}


def static_frontier(image, pair):
    """Inspect the null-return path; no enclosing-effect instructions execute."""
    body, offset = unit.code_at(image, RETURN, 0x62)
    instructions = {i.address: (i.mnemonic, i.op_str) for i in
                    capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32).disasm(body, RETURN)}
    expected = {
        0x6cf8f7: ("test", "eax, eax"), 0x6cf8f9: ("je", "0x6cf929"),
        0x6cf929: ("fld", "dword ptr [esi + 0x4d]"),
        0x6cf92c: ("fmul", "dword ptr [0x967f28]"),
        0x6cf953: ("mov", "edx, dword ptr [esi + 0x6d]"),
        0x6cf956: ("mov", "al, byte ptr [edx + 0x2d]"),
    }
    require(all(instructions.get(a) == value for a, value in expected.items()), "EFFECT_INSTRUCTION_MAP")
    require(pair["returned"]["eax"] == 0, "NULL_RETURN_FRONTIER_DOMAIN")
    slot = pair["returned"]["esi"]
    attributes = read(pair["after"], slot + 0x6d)
    require(all(slot + 0x4d + k in pair["after"] for k in range(4)), "SLOT_FLOAT_MISSING")
    require(attributes + 0x2d < 2**32 and attributes + 0x2d not in pair["after"],
            "ATTRIBUTE_FRONTIER_CHANGED")
    require(all(0x967f28 + k not in pair["after"] for k in range(4)), "CONSTANT_FRONTIER_CHANGED")
    constant_rva = 0x967f28 - image["base"]
    sections = [s for s in image["sections"] if s[2] <= constant_rva and constant_rva + 4 <= s[2] + s[3]]
    require(len(sections) == 1 and sections[0][5] & 0x40000000, "CONSTANT_PE_MAPPING")
    constant_offset = sections[0][4] + constant_rva - sections[0][2]
    return {"executed": False, "start_va": unit.hx(RETURN), "file_offset": unit.hx(offset),
            "bytes": len(body), "sha256": unit.sha(body),
            "first_uncaptured_constant_read_va": "006cf92c",
            "constant_va": "00967f28", "constant_file_offset": unit.hx(constant_offset),
            "first_missing_dynamic_read_va": "006cf956", "attribute_offset": 45, "width": 1}


def compare(args):
    try:
        data, record, kind = b2.parse_input(args.input)
        require(kind == "runtime-capture", "PAIRED_RAW_CAPTURE_REQUIRED")
        pair = admit_pair(record)
        # B2 independently admits the entry closure and freshly executes the
        # original instructions before calling its TypeScript comparator.
        with tempfile.TemporaryDirectory(prefix="reversal-paired-return-41-") as folder:
            replay_path = Path(folder) / "replay.json"
            result = b2.compare(argparse.Namespace(
                input=args.input, pinned=args.pinned, gdi=args.gdi, node=args.node,
                private_replay=replay_path))
            replay_bytes = replay_path.read_bytes()
            replay = json.loads(replay_bytes)
        require(result["input_sha256"] == unit.sha(data) and
                result["original_replay_sha256"] == unit.sha(replay_bytes), "PAIR_INPUT_CHANGED")
        case = replay["cases"][0]
        for name in unit.REGS:
            require(case["final"][name] == pair["returned"][name], "LIVE_REPLAY_REGISTER_MISMATCH")
        require(case["result"]["nonstack_memory_unchanged"] is True and
                result["comparison"]["shared_rng_unchanged"] is True, "REPLAY_EFFECT_MISMATCH")
        image = unit.read_pe(args.gdi, "gdi")
        require(record["return_code_sha256"] == unit.sha(unit.code_at(image, RETURN, 16)[0]),
                "RETURN_CODE_DIGEST")
        frontier = static_frontier(image, pair)
    except b2.Rejected:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, IndexError):
        raise b2.Rejected("paired-return", "PAIR_SHAPE_OR_DOMAIN") from None
    except OSError:
        raise b2.Rejected("paired-return", "PAIR_INPUT_UNREADABLE") from None
    return {"schema": SCHEMA, "status": "matched", "input_sha256": unit.sha(data),
            "executable_sha256": unit.EXPECTED["gdi"][0],
            "original_replay_sha256": unit.sha(replay_bytes),
            "entry_va": "0062e6e0", "return_va": "006cf8f7",
            "declared_live_pair": True, "provenance_authenticated": False,
            "live_pair_compared": True, "live_instruction_trace": False,
            "general_registers_compared": list(unit.REGS),
            "fixed_regions_compared": pair["fixed_regions"],
            "game_regions_unchanged": pair["game_regions"],
            "stable_bytes_compared": pair["stable_bytes"],
            "callee_scratch_changed": pair["scratch_changed"] > 0,
            "slot_staff_alias_both_boundaries": True, "slot_attribute_alias_both_boundaries": True,
            "fs_head_restored": True, "floating_areas_unchanged": True,
            "selected_rng_cells_unchanged": True,
            "original_to_typescript": {k: v for k, v in result["comparison"].items()
                                      if k != "live_return_observed"},
            "effect_frontier": frontier,
            "limits": ["two live boundaries; intervening execution untraced",
                       "cached null-return path only; no live ordered-effects trace",
                       "no effect completion, object lifetime or resolver-entry join",
                       "EFLAGS and scratch stack payload are not compared to replay"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "pinned", "gdi", "node"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare(args)
    except b2.Rejected as error:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "stage": error.stage, "code": error.code}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
