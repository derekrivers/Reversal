"""Reproduce R22-B normal/optimized extraction and negative integrity gates."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def demand(ok, message):
    if not ok:
        raise ValueError(message)


def run(command, expected_success):
    result = subprocess.run(command, capture_output=True, text=True)
    demand((result.returncode == 0) == expected_success,
           "unexpected extractor exit status: " + str(result.returncode) + " " + result.stderr[-400:])
    return result


def main(args):
    extractor = Path(__file__).with_name("extract_match_selection_22.py")
    with tempfile.TemporaryDirectory(prefix="match-selection-22-", dir=args.scratch) as scratch_name:
        scratch = Path(scratch_name)
        normal, optimized = scratch / "normal.json", scratch / "optimized.json"
        basic = [str(extractor), str(args.binary), "--exports", str(args.exports),
                 "--preflight", str(args.preflight), "--output"]
        run([sys.executable, *basic, str(normal)], True)
        run([sys.executable, "-O", *basic, str(optimized)], True)
        demand(normal.read_bytes() == optimized.read_bytes(), "normal/optimized evidence mismatch")
        parsed = json.loads(normal.read_text(encoding="utf-8"))
        demand(parsed["instruction_count"] == 832 and parsed["all_original_and_native_instructions_match"],
               "valid evidence is incomplete")

        bad_binary = scratch / "altered.exe"
        shutil.copyfile(args.binary, bad_binary)
        with bad_binary.open("r+b") as stream:
            stream.seek(0x2CEB9A)
            original = stream.read(1)
            stream.seek(0x2CEB9A)
            stream.write(bytes([original[0] ^ 1]))
        bad_export = scratch / "exports"
        shutil.copytree(args.exports, bad_export)
        asm = bad_export / "006ceb90.asm"
        asm.write_bytes(asm.read_bytes().replace(b"SUB ESP,0x224", b"SUB ESP,0x220", 1))

        negatives = {}
        for label, binary, exports in (("altered_specimen", bad_binary, args.exports),
                                       ("altered_native_operand", args.binary, bad_export)):
            for mode, prefix in (("normal", []), ("optimized", ["-O"])):
                output = scratch / (label + "-" + mode + ".json")
                cmd = [sys.executable, *prefix, str(extractor), str(binary),
                       "--exports", str(exports), "--preflight", str(args.preflight), "--output", str(output)]
                failure = run(cmd, False)
                demand(not output.exists(), "negative test wrote valid-looking output: " + label)
                negatives[label + "_" + mode] = {"rejected_before_output": True,
                                                   "error_class": "ValueError" if "ValueError:" in failure.stderr else "other"}
        demand(all(v["error_class"] == "ValueError" for v in negatives.values()),
               "integrity negative did not use explicit ValueError")
        return {"work_unit": "R22-B", "validation_scope": "extractor integrity, not original-instruction execution",
                "normal_optimized_output_identical": True, "generated_evidence_sha256": digest(normal),
                "negative_checks": negatives,
                "private_input_note": "Pinned executable and read-only checkpoint-21 exports remain outside Git"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, default=Path("results"))
    parser.add_argument("--output", type=Path, default=Path("evidence/match-selection-22-validation.json"))
    options = parser.parse_args()
    options.scratch.mkdir(parents=True, exist_ok=True)
    evidence = main(options)
    options.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("wrote " + str(options.output) + "; integrity checks only")
