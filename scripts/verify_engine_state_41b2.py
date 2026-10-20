"""Exercise the reusable CLI with genuine, metadata-reduced and synthetic input."""
from __future__ import annotations
import argparse
import base64
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import check_engine_state_41b2 as runner
import replay_engine_state_41 as unit
import verify_engine_state_41 as privacy


FILES = (
    "scripts/check_engine_state_41b2.py", "scripts/verify_engine_state_41b2.py",
    "reconstruction/compare-state-41b2.ts", "reports/engine-state-41b2.md",
)


def region(label, address, data):
    return {"label": label, "address": address, "requested": len(data), "received": len(data),
            "complete": True, "hex": data.hex(), "sha256": unit.sha(data)}


def synthetic(images, index, mapping, old_seh):
    """Authored sanitized fixture; never labelled an observed game entry."""
    staff_base, receiver, rows, cache, attributes = 0x200000, 0x210000, 0x220000, 0x230000, 0x240000
    participant, stack, fs_base = staff_base + 110 * index, 0x308000, 0x260000
    word = lambda value: struct.pack("<I", value & 0xffffffff)
    g, rng = unit.GLOBALS["gdi"], unit.RNG_GLOBALS["gdi"]
    date = 0x001a07ea + index
    reads = [
        region("lookup_flags", g["flags"], b"\xff"),
        region("staff_count", g["count"], word(64)),
        region("current_date", g["date"], word(date) + word(0x12345678)),
        region("lookup_global", g["lookup"], word(receiver)),
        region("staff_base", g["staff_base"], word(staff_base)),
    ]
    for label, key, value in (
        ("rng_cursor", "cursor", rng["table"] + 4 * (index + 5)),
        ("rng_offset", "offset", 999 + index),
        ("rng_limit", "limit", rng["table"] + 4 * 50999),
        ("crt_seed", "seed", 0x12345678 + index),
    ):
        reads.append(region(label, rng[key], word(value)))
    stack_bytes = bytearray(0x460)
    struct.pack_into("<II", stack_bytes, 0x260, 0x6cf8f7, participant)
    reads.append(region("entry_stack_below_and_arguments", stack - 0x260, bytes(stack_bytes[:0x300])))
    obj = bytearray(44); struct.pack_into("<III", obj, 0, rows, cache, 3)
    reads.append(region("lookup_receiver", receiver, bytes(obj)))
    staff = bytearray(110); struct.pack_into("<I", staff, 0, index); struct.pack_into("<I", staff, 0x61, attributes)
    reads.append(region("staff_record", participant, bytes(staff)))
    row = bytearray(31); struct.pack_into("<II", row, 0, date, 0x12345678); struct.pack_into("<i", row, 14, mapping)
    reads.append(region("selected_status_row", rows + 31 * index, bytes(row)))
    if mapping >= 0:
        reads.append(region("selected_cache_record", cache + 48 * mapping, bytes(48)))
    registers = {"eax": 0xdeadbeef, "ebx": 0x12345678, "ecx": receiver, "edx": 0x87654321,
                 "esi": 0x280000, "edi": 0xfeedface, "ebp": 0xcafef00d,
                 "esp": stack, "eip": 0x62e6e0, "eflags": 0x202}
    raw = {"schema": "reversal.runtime-capture-41.v1", "private": True,
           "profile": "gdi", "exe_sha256": unit.EXPECTED["gdi"][0], "hit": True, "detached": True,
           "module": {"base": 0x400000}, "breakpoint_runtime_va": 0x62e6e0, "restored_threads": [1],
           "boundary_code_sha256": unit.sha(unit.code_at(images["gdi"], 0x62e6e0, 16)[0]),
           "sample": {"registers": registers, "thread": 1,
                      "fs": {"complete": True, "base": fs_base,
                             "head": region("fs", fs_base, word(old_seh))},
                      "x87": {"control_word": 0x27f, "status_word": 0, "tag_word": 65535},
                      "memory": [region("stack", stack, bytes(stack_bytes[0x260:0x460]))],
                      "lookup_closure": {"all_requested_reads_complete": True, "memory": reads}}}
    return {"schema": runner.WRAPPER, "evidence_kind": "synthetic", "capture": raw}


def verify(args):
    images, _, _ = unit.evidence(args.pinned, args.gdi)
    source = args.capture.read_bytes()
    real = json.loads(source)
    # Removing irrelevant capture metadata leaves byte-addressed closure intact.
    reduced = {key: real[key] for key in
               ("schema", "private", "profile", "exe_sha256", "hit", "detached", "module",
                "breakpoint_runtime_va", "restored_threads", "boundary_code_sha256", "sample")}
    wrapper = {"schema": runner.WRAPPER, "evidence_kind": "sanitized-capture", "capture": reduced}
    fixtures = [
        ("runtime-capture", real, True, source),
        ("metadata-reduced-capture", wrapper, True, None),
        ("synthetic-null", synthetic(images, 7, -1, 0x30f000), True, None),
        ("synthetic-nonnull", synthetic(images, 31, 2, 0xfedcba98), False, None),
    ]
    raw_captures = [real]
    for index, path in enumerate(args.additional_capture):
        body = path.read_bytes()
        additional = json.loads(body)
        raw_captures.append(additional)
        fixtures.append(("additional-runtime-capture-" + str(index + 1), additional, True, body))
    unit.need(len({unit.sha(body) for _, _, _, body in fixtures if body is not None}) ==
              len(raw_captures), "duplicate genuine-capture fixture")
    masks = privacy.patterns(images)
    memory_regions = [item for record in raw_captures for item in
                      record["sample"]["lookup_closure"]["memory"] + record["sample"]["memory"]]
    for item in memory_regions:
        body = bytes.fromhex(item["hex"])
        for size in range(12, 33):
            for offset in range(len(body) - size + 1):
                sample = body[offset:offset + size]
                masks[0].add(sample); masks[1].add(sample.hex().encode())
        for size in range(9, 31, 3):
            for offset in range(len(body) - size + 1):
                masks[2].add(base64.b64encode(body[offset:offset + size]))
    results, rejected = [], []
    with tempfile.TemporaryDirectory(prefix="reversal-verify-41b2-") as folder:
        temp = Path(folder)
        def invoke(path, optimized=False, extra=()):
            process = subprocess.run(
                [sys.executable, "-B", *(["-O"] if optimized else []),
                 str(Path(runner.__file__)), "--input", str(path), "--pinned", str(args.pinned),
                 "--gdi", str(args.gdi), "--node", str(args.node), *extra],
                capture_output=True, timeout=45)
            unit.need(not process.stderr, "runner emitted unstructured/private stderr")
            parsed = json.loads(process.stdout)
            privacy.privacy(process.stdout, masks)
            return process.returncode, parsed, process.stdout
        for name, fixture, null, body in fixtures:
            path = temp / (name + ".json")
            path.write_bytes(body if body is not None else json.dumps(fixture).encode())
            normal, optimized = invoke(path), invoke(path, True)
            unit.need(normal[0] == optimized[0] == 0 and normal[2] == optimized[2], "CLI normal/-O differs")
            summary = normal[1]
            unit.need(summary["comparison"]["cases"][0]["returned_null"] is null, "result branch mismatch")
            unit.need(summary["declared_live_entry"] is (name[:9] != "synthetic") and
                      summary["provenance_authenticated"] is False, "synthetic provenance promoted")
            results.append({"name": name, "input_sha256": summary["input_sha256"],
                            "evidence_kind": summary["evidence_kind"],
                            "comparison": summary["comparison"]["cases"][0],
                            "altered_results_rejected": len(summary["comparison"]["altered_result_rejections"]),
                            "stdout_sha256": unit.sha(normal[2])})

        base = fixtures[3][1]
        def reseal(fixture, label, offset, value):
            raw = fixture["capture"]
            item = next(r for r in raw["sample"]["lookup_closure"]["memory"] if r["label"] == label)
            body = bytearray.fromhex(item["hex"]); body[offset:offset+4] = struct.pack("<I", value)
            item["hex"], item["sha256"] = body.hex(), unit.sha(body)
        def reject(name, mutate, code):
            fixture = copy.deepcopy(base); mutate(fixture)
            path = temp / (name + ".json"); path.write_text(json.dumps(fixture), encoding="utf-8")
            normal, optimized = invoke(path), invoke(path, True)
            unit.need(normal[0] == optimized[0] == 1 and normal[2] == optimized[2] and
                      normal[1]["code"] == code, "wrong rejection " + name)
            rejected.append({"name": name, "code": code})
        reject("resealed-stale-row", lambda f: reseal(f, "selected_status_row", 0, 0), "REFRESH_UPDATE_REQUIRED")
        def uninitialized(fixture):
            item = next(r for r in fixture["capture"]["sample"]["lookup_closure"]["memory"]
                        if r["label"] == "lookup_flags")
            item["hex"], item["sha256"] = "00", unit.sha(b"\0")
        reject("resealed-uninitialized-flags", uninitialized, "REFRESH_INITIALIZATION_REQUIRED")
        reject("resealed-lookup-alias", lambda f: reseal(f, "lookup_global", 0, 0), "LOOKUP_ALIAS_MISMATCH")
        reject("resealed-rng-cursor", lambda f: reseal(f, "rng_cursor", 0, 0), "RNG_STATE_OUTSIDE_DOMAIN")
        reject("missing-cache-referent", lambda f: reseal(f, "selected_status_row", 14, 3), "CACHE_REFERENT_MISSING")
        reject("missing-fs", lambda f: f["capture"]["sample"]["fs"].update(complete=False), "FS_STATE_MISSING")
        reject("invalid-hex", lambda f: f["capture"]["sample"]["lookup_closure"]["memory"][0].update(hex="gg"),
               "REGION_ENCODING")
        reject("unclaimed-input-kind", lambda f: f.update(evidence_kind="live-complete"), "INVALID_EVIDENCE_KIND")
        reject("wrapper-cannot-declare-raw-capture", lambda f: f.update(evidence_kind="runtime-capture"),
               "INVALID_EVIDENCE_KIND")
        reject("wrapper-extra-trust-field", lambda f: f.update(authenticated=True), "INVALID_WRAPPER")
        reject("malformed-register-object", lambda f: f["capture"]["sample"].update(registers=None),
               "REGISTER_SHAPE")
        reject("missed-breakpoint", lambda f: f["capture"].update(hit=False), "CAPTURE_OUTSIDE_CACHED_LOOKUP_DOMAIN")
        input_path = temp / "runtime-capture.json"
        replay_path = temp / "retained-private-replay.json"
        saved = invoke(input_path, extra=("--private-replay", str(replay_path)))
        unit.need(saved[0] == 0 and replay_path.exists(), "private replay not retained on request")
        blocked = invoke(input_path, extra=("--private-replay", str(replay_path)))
        unit.need(blocked[0] == 1 and blocked[1]["code"] == "PRIVATE_OUTPUT_EXISTS", "private file overwritten")
        rejected.append({"name": "existing-private-output", "code": "PRIVATE_OUTPUT_EXISTS"})
        blocked = invoke(input_path, extra=("--private-replay", str(unit.ROOT / "evidence/private-test.json")))
        unit.need(blocked[0] == 1 and blocked[1]["code"] == "PRIVATE_OUTPUT_LOCATION", "private output accepted in evidence")
        rejected.append({"name": "public-private-output", "code": "PRIVATE_OUTPUT_LOCATION"})
        # Corrupt an independently regenerated original result and exercise the
        # standalone TS CLI's JSON rejection without editing simulation inputs.
        altered = json.loads(replay_path.read_bytes())
        altered["cases"][0]["result"]["pointer"] ^= 1
        changed = temp / "altered-original-result.json"; changed.write_text(json.dumps(altered), encoding="utf-8")
        process = subprocess.run([str(args.node), str(unit.ROOT / "reconstruction/compare-state-41b2.ts"),
                                  str(changed)], capture_output=True, text=True, timeout=30)
        unit.need(process.returncode == 1 and not process.stderr and
                  json.loads(process.stdout)["code"] == "COMPARISON_REJECTED", "altered standalone result accepted")
        rejected.append({"name": "standalone-altered-original-return", "code": "COMPARISON_REJECTED"})
    for name in FILES:
        privacy.privacy((unit.ROOT / name).read_bytes(), masks)
    receipt = {"schema": "reversal.engine-state-41b2.validation.v1",
               "specimens": {name: identity[0] for name, identity in unit.EXPECTED.items()},
               "normal_optimized_identical": True, "positive_inputs": results, "negative_inputs": rejected,
               "capture_hash_is_runner_allowlist": False,
               "source_sha256": {name: unit.sha((unit.ROOT / name).read_bytes().replace(b"\r\n", b"\n")) for name in FILES},
               "privacy": "public files and CLI stdout scanned for selected original code and captured memory excerpts",
               "scope": "reusable admitted cached GDI lookup comparison; capture provenance is declared metadata; no live return or executed RNG draw"}
    encoded = (json.dumps(receipt, indent=2) + "\n").encode()
    privacy.privacy(encoded, masks); args.output.write_bytes(encoded)
    print(json.dumps({"positive_inputs": len(results), "negative_inputs": len(rejected),
                      "altered_result_probes": sum(r["altered_results_rejected"] for r in results),
                      "normal_optimized_equal": True, "privacy_scan": "passed"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pinned", type=Path, required=True); parser.add_argument("--gdi", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True); parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--additional-capture", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    verify(parser.parse_args())
