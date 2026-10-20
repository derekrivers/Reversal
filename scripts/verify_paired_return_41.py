"""Verify the paired-return checker and publish only a sanitized receipt."""
from __future__ import annotations
import argparse
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import check_paired_return_41 as checker
import replay_engine_state_41 as unit
import verify_engine_state_41 as privacy

FILES = ("scripts/check_paired_return_41.py", "scripts/verify_paired_return_41.py",
         "reports/engine-paired-return-41.md")
DEPENDENCIES = ("scripts/check_engine_state_41b2.py", "scripts/capture_engine_state_41.py",
                "scripts/replay_engine_state_41.py", "reconstruction/compare-state-41b2.ts",
                "reconstruction/engine-state-41.ts")


def seal(region, body):
    region["hex"], region["sha256"] = body.hex(), unit.sha(body)


def changed_return_byte(record, label, offset):
    """Reseal all aliases so changed state must fail comparison, not integrity."""
    before, after = record["sample"], record["return_sample"]
    target = next(r for r in after["entry_regions_after"] if r.get("label") == label)
    address = target["address"] + offset
    for item in after["entry_regions_after"] + after["memory"]:
        index = address - item["address"]
        if 0 <= index < item["requested"]:
            body = bytearray.fromhex(item["hex"])
            body[index] ^= 1
            seal(item, body)
    for original, current in zip(before["memory"] + before["lookup_closure"]["memory"],
                                 after["entry_regions_after"]):
        current["unchanged"] = current["sha256"] == original["sha256"]


def verify(args):
    images, _, _ = unit.evidence(args.pinned, args.gdi)
    raw = args.capture.read_bytes()
    record = json.loads(raw)
    masks = privacy.patterns(images)
    private_bodies = [unit.code_at(images["gdi"], checker.RETURN, 0x62)[0]]
    for sample in (record["sample"], record["return_sample"]):
        regions = sample["memory"] + sample.get("entry_regions_after", []) + [
            sample["fs"]["head"]] + sample.get("lookup_closure", {}).get("memory", [])
        private_bodies.extend(bytes.fromhex(item["hex"]) for item in regions)
        private_bodies.extend(bytes.fromhex(body) for body in (
            sample["extended_registers_hex"], sample["x87"]["legacy_register_area_hex"]))
    for body in private_bodies:
        for size in range(12, 33):
            for offset in range(len(body) - size + 1):
                value = body[offset:offset + size]
                masks[0].add(value); masks[1].add(value.hex().encode())
        for size in range(9, 31, 3):
            for offset in range(len(body) - size + 1):
                masks[2].add(base64.b64encode(body[offset:offset + size]))
    rejected = []
    with tempfile.TemporaryDirectory(prefix="reversal-verify-paired-41-") as folder:
        temp = Path(folder)
        def invoke(path, optimized=False):
            process = subprocess.run(
                [sys.executable, "-B", *(["-O"] if optimized else []), str(Path(checker.__file__)),
                 "--input", str(path), "--pinned", str(args.pinned), "--gdi", str(args.gdi),
                 "--node", str(args.node)], capture_output=True, timeout=45)
            unit.need(not process.stderr, "unstructured checker stderr")
            parsed = json.loads(process.stdout)
            privacy.privacy(process.stdout, masks)
            return process.returncode, parsed, process.stdout
        positive = temp / "pair.json"
        positive.write_bytes(raw)
        normal, optimized = invoke(positive), invoke(positive, True)
        unit.need(normal[0] == optimized[0] == 0 and normal[2] == optimized[2],
                  "paired normal/optimized result mismatch")
        result = normal[1]
        unit.need(result["live_pair_compared"] and not result["live_instruction_trace"] and
                  not result["provenance_authenticated"], "paired evidence scope changed")
        def reject(name, mutate, code):
            changed = copy.deepcopy(record)
            mutate(changed)
            path = temp / (name + ".json")
            path.write_text(json.dumps(changed), encoding="utf-8")
            one, two = invoke(path), invoke(path, True)
            unit.need(one[0] == two[0] == 1 and one[2] == two[2] and
                      one[1]["code"] == code, "wrong rejection: " + name)
            rejected.append({"name": name, "code": code})
        def reg(name):
            return lambda r: r["return_sample"]["registers"].update(
                {name: r["return_sample"]["registers"][name] ^ 1})
        reject("altered-live-eax", reg("eax"), "LIVE_REPLAY_REGISTER_MISMATCH")
        reject("altered-live-ecx", reg("ecx"), "LIVE_REPLAY_REGISTER_MISMATCH")
        reject("altered-return-esp", reg("esp"), "RETURN_STACK")
        reject("altered-return-eip", reg("eip"), "RETURN_ADDRESS")
        reject("altered-nonvolatile", reg("ebx"), "RETURN_NONVOLATILE")
        reject("different-thread", lambda r: r["return_sample"].update(thread=0), "RETURN_THREAD")
        reject("resealed-return-rng-change", lambda r: changed_return_byte(r, "rng_cursor", 0),
               "SELECTED_STATE_CHANGED")
        reject("resealed-return-row-change", lambda r: changed_return_byte(r, "selected_status_row", 0),
               "SELECTED_STATE_CHANGED")
        reject("resealed-return-slot-staff-change",
               lambda r: changed_return_byte(r, "effect_esi_candidate_slot", 0x69), "SLOT_STAFF_ALIAS")
        reject("resealed-return-slot-attribute-change",
               lambda r: changed_return_byte(r, "effect_esi_candidate_slot", 0x6d), "SLOT_ATTRIBUTE_ALIAS")
        def coherent_bad_slot(r):
            target = next(x for x in r["sample"]["lookup_closure"]["memory"]
                          if x["label"] == "effect_esi_candidate_slot")
            body = bytearray.fromhex(target["hex"]); body[0x69] ^= 1; seal(target, body)
            changed_return_byte(r, "effect_esi_candidate_slot", 0x69)
        reject("both-boundaries-invalid-slot-alias", coherent_bad_slot, "SLOT_STAFF_ALIAS")
        def fs_change(r):
            target = r["return_sample"]["fs"]["head"]
            body = bytearray.fromhex(target["hex"]); body[0] ^= 1; seal(target, body)
        reject("resealed-fs-head-change", fs_change, "RETURN_FS_CHANGED")
        reject("x87-control-change", lambda r: r["return_sample"]["x87"].update(control_word=0),
               "RETURN_X87_CHANGED")
        reject("missing-fixed-reread", lambda r: r["return_sample"]["entry_regions_after"].pop(),
               "FIXED_REREADS_MISSING")
        reject("invented-unchanged-effect", lambda r: next(
            x for x in r["return_sample"]["entry_regions_after"]
            if x.get("label") == "entry_stack_below_and_arguments").update(unchanged=True),
            "REREAD_EFFECT_METADATA")
        reject("wrong-return-code", lambda r: r.update(return_code_sha256="0" * 64), "RETURN_CODE_DIGEST")
        reject("missing-live-return", lambda r: r.update(return_observed=False), "LIVE_RETURN_MISSING")
        reject("inconsistent-pair-metadata", lambda r: r["pairing"].update(caller_matches=False), "PAIR_METADATA")
        def alias_change(r):
            target = r["return_sample"]["memory"][0]
            body = bytearray.fromhex(target["hex"]); body[0x18] ^= 1; seal(target, body)
        reject("resealed-overlapping-return-conflict", alias_change, "RETURN_ALIAS_CONFLICT")
        reject("reversed-timestamp", lambda r: r["return_sample"].update(
            captured_utc=r["sample"]["captured_utc"]), "PAIR_TIMESTAMP_ORDER")
    for name in FILES:
        privacy.privacy((unit.ROOT / name).read_bytes(), masks)
    # Check that the privacy gate itself refuses code and memory excerpts.
    privacy_rejections = 0
    for body in (private_bodies[0][:24], bytes.fromhex(record["sample"]["lookup_closure"]["memory"][-1]["hex"])):
        for value in (body[:24], body[:24].hex().encode(), base64.b64encode(body[:24])):
            refused = False
            try:
                privacy.privacy(value, masks)
            except ValueError:
                refused = True
            unit.need(refused, "private excerpt accepted")
            privacy_rejections += 1
    receipt = {"schema": "reversal.engine-paired-return-41.validation.v1",
               "comparison": result, "normal_optimized_identical": True,
               "negative_inputs": rejected, "privacy_negative_probes": privacy_rejections,
               "source_sha256": {name: unit.sha((unit.ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
                                 for name in (*FILES, *DEPENDENCIES)},
               "privacy": "public files and stdout scanned for selected code, memory and floating-register excerpts",
               "scope": "one genuine null cached-lookup pair; no live instruction trace or enclosing effect completion"}
    encoded = (json.dumps(receipt, indent=2) + "\n").encode()
    privacy.privacy(encoded, masks)
    args.output.write_bytes(encoded)
    print(json.dumps({"paired_inputs": 1, "live_negative_inputs": len(rejected),
                      "typescript_altered_result_probes": len(result["original_to_typescript"]["altered_result_rejections"]),
                      "privacy_negative_probes": privacy_rejections, "normal_optimized_equal": True,
                      "privacy_scan": "passed"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "pinned", "gdi", "node", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    verify(parser.parse_args())
