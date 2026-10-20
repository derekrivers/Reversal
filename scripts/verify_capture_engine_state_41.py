"""Verify the identified private R41-A capture replay; publish digests only."""
from __future__ import annotations
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys

import capture_engine_state_41 as capture
import replay_engine_state_41 as unit
import verify_engine_state_41 as integrity


CAPTURE = "5359421a6164e301f32a4f406cbebdbe9458d4fcede5fa259c7e977066e90271"
PUBLIC = (
    "scripts/capture_engine_state_41.py", "scripts/verify_capture_engine_state_41.py",
    "reconstruction/check-captured-state-41.ts", "reports/engine-state-41.md",
)


def verify(args):
    source = args.capture.read_bytes()
    unit.need(unit.sha(source) == CAPTURE, "unexpected capture identity")
    record = json.loads(source)
    images, decoded, mapping = unit.evidence(args.pinned, args.gdi)
    captured = capture.admit(record)
    replayed = capture.generate(args.pinned, args.gdi, args.capture)
    case = replayed["cases"][0]
    private = (json.dumps(replayed, indent=2) + "\n").encode()
    output = unit.ROOT / "results/engine-state-41-captured-oracle.json"
    unit.need(output.exists() and output.read_bytes() == private, "retained private replay differs")
    for suffix, mode in (("normal", []), ("optimized", ["-O"])):
        reproduced = unit.ROOT / ("results/engine-state-41-captured-" + suffix + ".json")
        subprocess.run([sys.executable, "-B", *mode, str(Path(capture.__file__)),
                        str(args.pinned), str(args.gdi), str(args.capture), "--output", str(reproduced)],
                       check=True, capture_output=True, text=True)
        unit.need(reproduced.read_bytes() == private, suffix + " captured replay differs")

    negatives = []
    def reject(name, change):
        altered = copy.deepcopy(record)
        change(altered)
        try:
            capture.admit(altered)
        except (ValueError, KeyError):
            negatives.append(name)
            return
        raise ValueError("accepted altered capture: " + name)

    def region(raw, name):
        return next(item for item in raw["sample"]["lookup_closure"]["memory"] if item["label"] == name)

    def reseal(raw, name, offset, data):
        item = region(raw, name)
        content = bytearray.fromhex(item["hex"])
        content[offset:offset + len(data)] = data
        item["hex"], item["sha256"] = content.hex(), unit.sha(content)

    reject("wrong-executable", lambda r: r.update(exe_sha256=unit.EXPECTED["pinned"][0]))
    reject("missed-boundary", lambda r: r.update(hit=False))
    reject("not-detached", lambda r: r.update(detached=False))
    reject("unrestored-captured-thread", lambda r: r.update(restored_threads=[]))
    reject("wrong-entry", lambda r: r["sample"]["registers"].update(eip=0x62e6e1))
    reject("missing-FS-head", lambda r: r["sample"]["fs"].update(complete=False))
    reject("misaddressed-row", lambda r: region(r, "selected_status_row").update(address=1))
    reject("resealed-lookup-alias", lambda r: reseal(r, "lookup_global", 0, b"\0" * 4))
    reject("resealed-staff-base-alias", lambda r: reseal(r, "staff_base", 0, b"\0" * 4))
    reject("resealed-missing-init-bit", lambda r: reseal(r, "lookup_flags", 0, b"\x06"))
    reject("resealed-stale-row", lambda r: reseal(r, "selected_status_row", 0, b"\0" * 4))
    reject("missing-cache-referent", lambda r: reseal(r, "selected_status_row", 14, b"\0" * 4))
    reject("resealed-cursor-outside-table", lambda r: reseal(r, "rng_cursor", 0, b"\0" * 4))
    reject("resealed-conflicting-stack-alias", lambda r: reseal(r, "entry_stack_below_and_arguments",
                                                             0x260, b"\0" * 4))

    masks = integrity.patterns(images)
    # Protect captured original data as well as instructions. Each aligned
    # nine-byte base64 interior detects a 12-byte source excerpt at any phase.
    for region_ in captured["regions"]:
        body = bytes.fromhex(region_["hex"])
        for size in range(12, 33):
            for offset in range(len(body) - size + 1):
                sample = body[offset:offset + size]
                masks[0].add(sample); masks[1].add(sample.hex().encode())
        for size in range(9, 31, 3):
            for offset in range(len(body) - size + 1):
                masks[2].add(base64.b64encode(body[offset:offset + size]))
    for name in PUBLIC:
        integrity.privacy((unit.ROOT / name).read_bytes(), masks)
    # Scan the base model and public synthetic evidence as well.
    for name in ("reconstruction/engine-state-41.ts", "evidence/engine-state-41-oracle.json"):
        integrity.privacy((unit.ROOT / name).read_bytes(), masks)

    model = subprocess.run([str(args.node), str(unit.ROOT / "reconstruction/check-captured-state-41.ts"),
                            str(output)], check=True, capture_output=True, text=True)
    comparison = json.loads(model.stdout)
    unit.need(comparison["originalReplaySha256"] == unit.sha(private), "TS compared different replay")
    receipt = {
        "schema": "reversal.engine-state-41.captured-validation.v1",
        "capture_sha256": CAPTURE, "capture_tool_sha256": record["tool_sha256"],
        "executable_sha256": record["exe_sha256"], "source_branch": "GDI",
        "live_entry_observed": True, "live_return_observed": False,
        "entry_va": "0062e6e0", "caller_return_va": "006cf8f7",
        "normal_and_optimized_replay_identical": True,
        "original_replay_sha256": unit.sha(private),
        "original_instruction_steps": case["instruction_steps"],
        "ordered_nonstack_memory_events": len(case["events"]),
        "nested_call_boundaries": len(case["boundaries"]),
        "returned_null": True, "shared_rng_unchanged": True, "nonstack_memory_unchanged": True,
        "fs_normalization": "captured FS:[0] value at emulator address zero; actual stack addresses retained; no exception or callback executed",
        "typescript_negative_probes": comparison["negativeProbes"],
        "capture_admission_negative_probes": negatives,
        "privacy": "public files scanned against overlapping captured-data and selected-code windows; raw replay stays private",
        "source_sha256": {name: unit.sha((unit.ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
                          for name in PUBLIC},
        "scope": "one genuine GDI lookup-entry state replayed through cached refresh and return; no live return, effect completion, slot lifetime or resolver-entry join",
    }
    encoded = (json.dumps(receipt, indent=2) + "\n").encode()
    integrity.privacy(encoded, masks)
    args.output.write_bytes(encoded)
    print(json.dumps({"captured_cases": 1, "original_steps": case["instruction_steps"],
                      "python_negative_probes": len(negatives),
                      "typescript_negative_probes": comparison["negativeProbes"],
                      "normal_optimized_equal": True, "public_private_data_scan": "passed"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned", type=Path); parser.add_argument("gdi", type=Path)
    parser.add_argument("capture", type=Path); parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    verify(parser.parse_args())
