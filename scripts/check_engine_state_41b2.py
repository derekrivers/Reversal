"""Headless cached-lookup admission, original replay and TypeScript comparison.

Only JSON summaries go to stdout. Captured memory is passed to Node through an
ephemeral private file and removed afterward. No game/process access is used.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import capture_engine_state_41 as prior
import replay_engine_state_41 as original


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "reversal.engine-state-41b2.result.v1"
WRAPPER = "reversal.engine-state-41b2.input.v1"
MAX_BYTES = 4 * 1024 * 1024
DOMAIN_CODES = {
    "stale row enters unadmitted refresh update": "REFRESH_UPDATE_REQUIRED",
    "lookup static initialization remains required": "REFRESH_INITIALIZATION_REQUIRED",
    "missing FS head": "FS_STATE_MISSING",
    "incomplete lookup closure": "MEMORY_CLOSURE_INCOMPLETE",
    "missing captured memory": "MEMORY_CLOSURE_INCOMPLETE",
    "inconsistent captured aliases": "CAPTURE_ALIAS_CONFLICT",
    "lookup global/receiver alias mismatch": "LOOKUP_ALIAS_MISMATCH",
    "staff allocation/index alias mismatch": "PARTICIPANT_ALIAS_MISMATCH",
    "entry return address is not the mapped effect call": "UNSUPPORTED_CALLER",
    "staff signed index/count outside admission": "PARTICIPANT_RANGE",
    "missing mapped cache referent": "CACHE_REFERENT_MISSING",
    "RNG cells outside established table/cursor contract": "RNG_STATE_OUTSIDE_DOMAIN",
    "null-attribute branch outside cached admission": "NULL_ATTRIBUTES_OUTSIDE_DOMAIN",
}


class Rejected(ValueError):
    def __init__(self, stage, code):
        super().__init__(code)
        self.stage, self.code = stage, code


def demand(ok, stage, code):
    if not ok:
        raise Rejected(stage, code)


def parse_input(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    demand(len(data) <= MAX_BYTES, "input", "INPUT_BUDGET")
    try:
        raw = json.loads(data, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, UnicodeError):
        raise Rejected("input", "INVALID_JSON") from None
    demand(isinstance(raw, dict), "input", "INVALID_ENVELOPE")
    kind = "runtime-capture"
    if raw.get("schema") == WRAPPER:
        demand(set(raw) == {"schema", "evidence_kind", "capture"}, "input", "INVALID_WRAPPER")
        kind = raw["evidence_kind"]
        demand(kind in ("sanitized-capture", "synthetic"), "input", "INVALID_EVIDENCE_KIND")
        capture = raw["capture"]
    else:
        capture = raw
    demand(isinstance(capture, dict), "input", "INVALID_CAPTURE")
    try:
        sample = capture["sample"]
        demand(isinstance(sample, dict), "admission", "MISSING_CAPTURE_FIELDS")
        regs = sample["registers"]
        demand(isinstance(regs, dict), "admission", "REGISTER_SHAPE")
        demand(all(type(regs.get(n)) is int and 0 <= regs[n] < 2**32
                   for n in (*original.REGS, "eflags")), "admission", "REGISTER_SHAPE")
        closure = sample["lookup_closure"]
        demand(isinstance(closure, dict) and isinstance(closure["memory"], list) and
               isinstance(sample.get("memory", []), list) and isinstance(sample["fs"], dict),
               "admission", "MISSING_CAPTURE_FIELDS")
        demand(type(sample["fs"]["base"]) is int and 0 < sample["fs"]["base"] < 2**32 - 4,
               "admission", "FS_STATE_SHAPE")
        demand(isinstance(sample["x87"], dict) and all(
            type(sample["x87"].get(n)) is int and 0 <= sample["x87"][n] <= 65535
            for n in ("control_word", "status_word", "tag_word")), "admission", "X87_STATE_SHAPE")
        regions = closure["memory"] + sample.get("memory", []) + [sample["fs"]["head"]]
        demand(0 < len(regions) <= 128, "admission", "REGION_BUDGET")
        total = 0
        for item in regions:
            demand(isinstance(item, dict), "admission", "REGION_SHAPE")
            address, size, received = item["address"], item["requested"], item["received"]
            demand(type(address) is int and type(size) is int and type(received) is int and
                   0 <= address < 2**32 and 0 < size <= 4096 and address + size <= 2**32,
                   "admission", "REGION_SHAPE")
            text = item["hex"]
            demand(isinstance(text, str) and len(text) == 2 * size and
                   re.fullmatch("[0-9a-fA-F]+", text) is not None, "admission", "REGION_ENCODING")
            total += size
        demand(total <= 65536, "admission", "REGION_BUDGET")
    except (KeyError, TypeError, AttributeError):
        raise Rejected("admission", "MISSING_CAPTURE_FIELDS") from None
    # This digest identifies the supplied input; it is never an allow-list.
    return data, capture, kind


def compare(args):
    try:
        data, record, kind = parse_input(args.input)
    except OSError:
        raise Rejected("input", "INPUT_UNREADABLE") from None
    if args.private_replay:
        target = args.private_replay.resolve()
        demand(not target.is_relative_to(ROOT) or target.is_relative_to(ROOT / "results"),
               "output", "PRIVATE_OUTPUT_LOCATION")
        demand(not target.exists(), "output", "PRIVATE_OUTPUT_EXISTS")
    try:
        admitted = prior.admit(record)
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError) as error:
        raise Rejected("admission", DOMAIN_CODES.get(str(error), "CAPTURE_OUTSIDE_CACHED_LOOKUP_DOMAIN")) from None
    # The cached subsystem contract requires game data to be stable across
    # scratch-frame writes. Reject aliasing into the active nested stack frame.
    stack = admitted["initial"]["esp"]
    roles = record["sample"]["lookup_closure"]["memory"]
    for item in roles:
        if item["label"] != "entry_stack_below_and_arguments":
            demand(item["address"] + item["requested"] <= stack - 0x260 or
                   item["address"] >= stack + 0xa0, "admission", "STATE_ALIASES_STACK")
    fs_base = record["sample"]["fs"]["base"]
    demand(fs_base + 4 <= stack - 0x260 or fs_base >= stack + 0xa0,
           "admission", "FS_ALIASES_STACK")
    try:
        images, decoded, mapping = original.evidence(args.pinned, args.gdi)
    except (OSError, ValueError):
        raise Rejected("specimen", "SPECIMEN_OR_INSTRUCTION_MAP_REJECTED") from None
    demand(record.get("boundary_code_sha256") ==
           original.sha(original.code_at(images["gdi"], 0x62e6e0, 16)[0]),
           "admission", "ENTRY_CODE_DIGEST")
    # Capture regions may not replace executable bytes or the normalized FS cell.
    code_pages = {address & ~0xfff for address in decoded["gdi"]}
    for region in admitted["regions"]:
        address, size = region["address"], len(region["hex"]) // 2
        pages = set(range(address & ~0xfff, (address + size + 0xfff) & ~0xfff, 0x1000))
        demand(not pages & code_pages, "admission", "CAPTURE_OVERLAPS_CODE")
    try:
        controls = [original.execute(images, decoded, "gdi", case)
                    for case in original.synthetic_schedule()]
        allowed = {int(site, 16) for case in controls for site in case["trace"]}
        case = prior.replay(images, decoded, admitted, allowed)
    except Exception:
        raise Rejected("original-replay", "ORIGINAL_REPLAY_REJECTED") from None
    capture_bytes = data if kind == "runtime-capture" else json.dumps(record, separators=(",", ":")).encode()
    replay = {"schema": "reversal.engine-state-41.capture-replay.v1", "private": True,
              "source_capture_sha256": original.sha(capture_bytes), "mapping": mapping, "cases": [case]}
    serialized = (json.dumps(replay, indent=2) + "\n").encode()
    try:
        with tempfile.TemporaryDirectory(prefix="reversal-state-41b2-") as folder:
            private = Path(folder) / "replay.json"
            private.write_bytes(serialized)
            checked = subprocess.run([str(args.node), str(ROOT / "reconstruction/compare-state-41b2.ts"),
                                      str(private)], capture_output=True, text=True, timeout=30)
        result = json.loads(checked.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise Rejected("typescript", "TYPESCRIPT_RUNNER_FAILED") from None
    demand(checked.returncode == 0 and result.get("status") == "matched",
           "typescript", "TYPESCRIPT_COMPARISON_REJECTED")
    demand(result.get("original_replay_sha256") == original.sha(serialized),
           "typescript", "REPLAY_DIGEST_MISMATCH")
    if args.private_replay:
        try:
            args.private_replay.parent.mkdir(parents=True, exist_ok=True)
            with args.private_replay.open("xb") as stream:
                stream.write(serialized)
        except OSError:
            raise Rejected("output", "PRIVATE_OUTPUT_WRITE_FAILED") from None
    return {"schema": SCHEMA, "status": "matched", "input_sha256": original.sha(data),
            "evidence_kind": kind, "input_capture_sha256": replay["source_capture_sha256"],
            "original_replay_sha256": original.sha(serialized),
            "executable_sha256": original.EXPECTED["gdi"][0],
            "entry_va": "0062e6e0", "caller_return_va": "006cf8f7",
            "comparison": result, "declared_live_entry": kind != "synthetic",
            "provenance_authenticated": False,
            "live_return_observed": False, "rng_calls": 0,
            "limits": ["cached row only", "GDI effect-to-lookup boundary only",
                       "FS head address normalized; no exceptions",
                       "no effect completion, slot lifetime or resolver-entry join"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--pinned", type=Path, required=True)
    parser.add_argument("--gdi", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path("node"))
    parser.add_argument("--private-replay", type=Path)
    args = parser.parse_args()
    try:
        result = compare(args)
    except Rejected as error:
        print(json.dumps({"schema": SCHEMA, "status": "rejected", "stage": error.stage, "code": error.code}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
