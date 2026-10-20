"""Offline admission and replay of R41-A's private GDI lookup-entry capture.

No process access. Replay executes identified original instructions from captured
registers and represented memory. FS:[0] is relocated to an isolated emulator
cell with the captured head value; no exception/callback path is admitted.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import unicorn
from unicorn import x86_const as x
import replay_engine_state_41 as unit


def admit(raw):
    need = unit.need
    need(raw.get("schema") == "reversal.runtime-capture-41.v1" and raw.get("private") is True,
         "unsupported capture envelope")
    need(raw.get("exe_sha256") == unit.EXPECTED["gdi"][0] and raw.get("profile") == "gdi",
         "capture executable mismatch")
    need(raw.get("hit") is True and raw.get("detached") is True, "capture did not complete interception")
    need(raw["module"]["base"] == 0x400000 and raw["breakpoint_runtime_va"] == 0x62e6e0,
         "unsupported load address or entry")
    sample = raw["sample"]
    regs = sample["registers"]
    need(regs["eip"] == 0x62e6e0, "captured EIP differs from lookup entry")
    need(sample["thread"] in raw.get("restored_threads", []), "captured thread not restored")
    need(sample.get("fs", {}).get("complete") is True, "missing FS head")
    closure = sample["lookup_closure"]
    need(closure.get("all_requested_reads_complete") is True, "incomplete lookup closure")
    source = (closure["memory"] + [dict(sample["fs"]["head"], label="fs_head")] +
              [dict(region, label="additional_" + str(index))
               for index, region in enumerate(sample.get("memory", []))])
    labels, memory = {}, {}
    for region in source:
        label, address, size = region["label"], region["address"], region["requested"]
        need(label not in labels, "duplicate capture label")
        data = bytes.fromhex(region["hex"])
        need(region["complete"] is True and region["received"] == size == len(data) and
             unit.sha(data) == region["sha256"], "captured region hash/length mismatch")
        need(0 <= address and address + size <= 2**32 and size <= 4096, "unbounded capture region")
        labels[label] = region
        for index, value in enumerate(data):
            loc = address + index
            need(loc not in memory or memory[loc] == value, "inconsistent captured aliases")
            memory[loc] = value

    def read(address, size=4):
        need(all(address + k in memory for k in range(size)), "missing captured memory")
        return int.from_bytes(bytes(memory[address + k] for k in range(size)), "little")

    g, r = unit.GLOBALS["gdi"], unit.RNG_GLOBALS["gdi"]
    stack, receiver = regs["esp"], regs["ecx"]
    participant = read(stack + 4)
    need(read(stack) == 0x6cf8f7, "entry return address is not the mapped effect call")
    need(receiver != 0 and participant != 0, "null lookup/participant")
    for label, address, size in (
        ("lookup_flags", g["flags"], 1), ("staff_count", g["count"], 4),
        ("current_date", g["date"], 8), ("lookup_global", g["lookup"], 4),
        ("staff_base", g["staff_base"], 4),
        ("lookup_receiver", receiver, 44), ("staff_record", participant, 110),
        ("entry_stack_below_and_arguments", stack - 0x260, 0x300),
        ("rng_cursor", r["cursor"], 4), ("rng_offset", r["offset"], 4),
        ("rng_limit", r["limit"], 4), ("crt_seed", r["seed"], 4),
        ("fs_head", sample["fs"]["base"], 4),
    ):
        need(label in labels and labels[label]["address"] == address and labels[label]["requested"] == size,
             "missing or misaddressed " + label)
    index, count = read(participant), read(g["count"])
    need(0 <= index < count < 0x80000000, "staff signed index/count outside admission")
    need(read(g["staff_base"]) + 110 * index == participant, "staff allocation/index alias mismatch")
    need(read(g["lookup"]) == receiver, "lookup global/receiver alias mismatch")
    need(read(g["flags"], 1) & 7 == 7, "lookup static initialization remains required")
    need(read(participant + 0x61) != 0, "null-attribute branch outside cached admission")
    row = read(receiver) + 31 * index
    need(0 < row < 2**32 - 31, "row arithmetic overflow or null")
    need(labels["selected_status_row"]["address"] == row and
         labels["selected_status_row"]["requested"] == 31, "row alias/extent mismatch")
    need(read(row) == read(g["date"]), "stale row enters unadmitted refresh update")
    mapping = read(row + 14)
    if mapping == 0xffffffff:
        expected = 0
    else:
        need(mapping < 0x80000000, "negative cache index")
        expected = read(receiver + 4) + 48 * mapping
        need(0 < expected < 2**32 - 48 and
             labels.get("selected_cache_record", {}).get("address") == expected and
             labels["selected_cache_record"]["requested"] == 48, "missing mapped cache referent")
    cursor, limit = read(r["cursor"]), read(r["limit"])
    need(limit == r["table"] + 4 * 50999 and r["table"] <= cursor <= limit and
         (cursor - r["table"]) % 4 == 0 and read(r["offset"]) <= 65535,
         "RNG cells outside established table/cursor contract")
    cw = sample["x87"]["control_word"] & 0xffff
    need(cw in (0x27f, 0x37f), "unvalidated captured x87 control")
    fs_head = read(sample["fs"]["base"])
    regions = [{"address": region["address"], "hex": region["hex"]}
               for region in source if region["label"] != "fs_head"]
    regions.append({"address": 0, "hex": fs_head.to_bytes(4, "little").hex()})
    need(all(item["address"] != 0 for item in regions[:-1]), "capture aliases emulator FS cell")
    return {"regions": regions, "initial": regs, "participant": participant, "receiver": receiver,
            "row": row, "mapping": -1 if mapping == 0xffffffff else mapping, "expected": expected,
            "return_address": read(stack), "old_seh": fs_head, "x87_control": cw,
            "x87_status": sample["x87"]["status_word"] & 0xffff,
            "x87_tag": sample["x87"]["tag_word"] & 0xffff,
            "rng": {"cursorIndex": (cursor - r["table"]) // 4, "offset": read(r["offset"]),
                    "crtState": read(r["seed"])},
            "thread": sample["thread"], "fs_base": sample["fs"]["base"]}


def replay(images, decoded, captured, allowed):
    need, hx, sha = unit.need, unit.hx, unit.sha
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    memory = {}
    for region in captured["regions"]:
        for offset, value in enumerate(bytes.fromhex(region["hex"])):
            memory[region["address"] + offset] = value
    pages = {address & ~0xfff for address in memory}
    pages.update(address & ~0xfff for address in allowed)
    pages.add(captured["return_address"] & ~0xfff)
    for page in sorted(pages):
        uc.mem_map(page, 0x1000)
    for _, _, start, size in unit.RANGES[:4]:
        uc.mem_write(start, unit.code_at(images["gdi"], start, size)[0])
    for region in captured["regions"]:
        uc.mem_write(region["address"], bytes.fromhex(region["hex"]))
    for name, reg in unit.REGS.items():
        uc.reg_write(reg, captured["initial"][name])
    uc.reg_write(x.UC_X86_REG_EFLAGS, captured["initial"]["eflags"])
    uc.reg_write(x.UC_X86_REG_FPCW, captured["x87_control"])
    uc.reg_write(x.UC_X86_REG_FPSW, captured["x87_status"])
    uc.reg_write(x.UC_X86_REG_FPTAG, captured["x87_tag"])
    stack, row = captured["initial"]["esp"], captured["row"]
    rg = unit.RNG_GLOBALS["gdi"]
    read = lambda a, n=4: int.from_bytes(uc.mem_read(a, n), "little")
    rng_bytes = lambda: b"".join(bytes(uc.mem_read(rg[k], 4)) for k in ("cursor", "offset", "limit", "seed"))
    trace, events, boundaries = [], [], []
    current = 0

    def code(machine, address, size, _):
        nonlocal current
        current = address
        if address == captured["return_address"]:
            machine.emu_stop(); return
        need(address in allowed, "capture enters unsupported original path at " + hx(address))
        trace.append(hx(address)); need(len(trace) < 160, "capture instruction budget")
        if address in (0x62e76c, 0x62e771):
            kind = "refresh-call" if address == 0x62e76c else "refresh-return"
            boundaries.append({"kind": kind, "site": hx(address), "receiver": uc.reg_read(x.UC_X86_REG_ECX),
                "stack": uc.reg_read(x.UC_X86_REG_ESP),
                "argument": read(uc.reg_read(x.UC_X86_REG_ESP)) if kind == "refresh-call" else None,
                "rng_sha256": sha(rng_bytes()), "row_sha256": sha(bytes(uc.mem_read(row, 31)))})

    def mem(machine, access, address, size, value, _):
        need(all(address + k in memory for k in range(size)), "original accessed uncaptured memory")
        if stack - 0x260 <= address and address + size <= stack + 0xa0:
            return
        kind = "read" if access == unicorn.UC_MEM_READ else "write"
        events.append([hx(current), kind, hx(address), size,
                       read(address, size) if kind == "read" else value & ((1 << (size * 8)) - 1)])

    uc.hook_add(unicorn.UC_HOOK_CODE, code)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, mem)
    uc.emu_start(captured["initial"]["eip"], captured["return_address"], count=160)
    final = {name: uc.reg_read(reg) for name, reg in unit.REGS.items()}
    need(final["eip"] == captured["return_address"] and final["esp"] == stack + 8 and
         final["eax"] == captured["expected"], "captured original return mismatch")
    need(all(final[n] == captured["initial"][n] for n in ("ebx", "esi", "edi", "ebp")),
         "captured nonvolatile register change")
    need("0062c100" in trace and len(boundaries) == 2, "cached-refresh path was not completed")
    for address, value in memory.items():
        if not stack - 0x260 <= address < stack + 0xa0:
            need(read(address, 1) == value, "captured nonstack memory changed")
    need(uc.reg_read(x.UC_X86_REG_FPCW) == captured["x87_control"] and
         uc.reg_read(x.UC_X86_REG_FPSW) == captured["x87_status"] and
         uc.reg_read(x.UC_X86_REG_FPTAG) == captured["x87_tag"], "captured x87 metadata changed")
    return {"build": "gdi", "capture": captured, "initial": captured["initial"], "final": final,
            "trace": trace, "events": events, "boundaries": boundaries,
            "result": {"pointer": final["eax"], "mapping": captured["mapping"], "row": row,
                       "rng": captured["rng"], "x87_control": captured["x87_control"],
                       "nonstack_memory_unchanged": True}, "instruction_steps": len(trace)}


def generate(pinned, gdi, capture):
    raw = capture.read_bytes()
    record = json.loads(raw)
    captured = admit(record)
    images, decoded, mapping = unit.evidence(pinned, gdi)
    live_hash = record.get("boundary_code_sha256")
    need = unit.need
    need(live_hash == unit.sha(unit.code_at(images["gdi"], 0x62e6e0, 16)[0]),
         "captured entry code differs from identified disk image")
    synthetic = [unit.execute(images, decoded, "gdi", case) for case in unit.synthetic_schedule()]
    allowed = {int(site, 16) for case in synthetic for site in case["trace"]}
    case = replay(images, decoded, captured, allowed)
    return {"schema": "reversal.engine-state-41.capture-replay.v1", "private": True,
            "source_capture_sha256": unit.sha(raw), "mapping": mapping, "cases": [case],
            "scope": "original-instruction emulation from genuine GDI lookup entry; FS address normalized with captured value; no live return or resolver join"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned", type=Path); parser.add_argument("gdi", type=Path)
    parser.add_argument("capture", type=Path); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need = unit.need
    need(args.output.resolve().is_relative_to(unit.ROOT / "results"), "private replay output must be under results/")
    result = generate(args.pinned, args.gdi, args.capture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"admitted": True, "cases": 1, "steps": result["cases"][0]["instruction_steps"],
                      "capture_sha256": result["source_capture_sha256"], "live_return_observed": False}))


if __name__ == "__main__":
    main()
