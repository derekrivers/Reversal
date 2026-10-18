#!/usr/bin/env python3
"""Reproduce R23-A normal/-O output and reject changed private inputs and oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, success):
    result = subprocess.run(command, capture_output=True, text=True)
    need((result.returncode == 0) == success,
         "unexpected exit code " + str(result.returncode) + " " + result.stderr[-500:])
    return result


def check(args):
    scripts = Path(__file__).resolve().parent
    extractor, emulator = scripts / "extract_match_status_23.py", scripts / "emulate_match_status_23.py"
    with tempfile.TemporaryDirectory(prefix="match-status-23-", dir=args.scratch) as temp_name:
        temp = Path(temp_name)
        products = {}
        for title, script in (("sites", extractor), ("oracle", emulator)):
            for mode, flag in (("normal", []), ("optimized", ["-O"])):
                output = temp / f"{title}-{mode}.json"
                run([sys.executable, *flag, str(script), str(args.binary), "--exports", str(args.exports),
                     "--preflight", str(args.preflight), "--output", str(output)], True)
                products[(title, mode)] = output
            need(products[(title, "normal")].read_bytes() == products[(title, "optimized")].read_bytes(),
                 title + " normal/-O mismatch")
        sites = json.loads(products[("sites", "normal")].read_text(encoding="utf-8"))
        oracle = json.loads(products[("oracle", "normal")].read_text(encoding="utf-8"))
        need(sites["instruction_count"] == 88 and sites["all_original_and_native_instructions_match"],
             "static-body check incomplete")
        need(oracle["function_cases"] == 43 and oracle["executed_instruction_steps"] == 688,
             "original oracle incomplete")
        need(products[("sites", "normal")].read_bytes() == args.sites.read_bytes(), "retained site evidence differs")
        need(products[("oracle", "normal")].read_bytes() == args.oracle.read_bytes(), "retained oracle differs")

        wrong = temp / "altered.exe"
        shutil.copyfile(args.binary, wrong)
        with wrong.open("r+b") as stream:
            stream.seek(0x22C400)
            original = stream.read(1)
            stream.seek(0x22C400)
            stream.write(bytes([original[0] ^ 1]))
        bad_exports = temp / "exports"
        shutil.copytree(args.exports, bad_exports)
        asm = bad_exports / "0062c400.asm"
        original_asm = asm.read_bytes()
        changed_asm = original_asm.replace(b"SUB ESP,0x208", b"SUB ESP,0x204", 1)
        need(changed_asm != original_asm, "native operand mutation failed")
        asm.write_bytes(changed_asm)
        negatives = {}
        for label, binary, exports in (("altered_specimen", wrong, args.exports),
                                       ("altered_native_operand", args.binary, bad_exports)):
            for mode, flag in (("normal", []), ("optimized", ["-O"])):
                output = temp / f"{label}-{mode}.json"
                failure = run([sys.executable, *flag, str(extractor), str(binary), "--exports", str(exports),
                               "--preflight", str(args.preflight), "--output", str(output)], False)
                need(not output.exists() and "ValueError:" in failure.stderr, "negative wrote output or lacked explicit error")
                negatives[label+"_"+mode] = {"rejected_before_output": True, "error_class": "ValueError"}
        # Reseal the changed export for this local diagnostic only. The pinned
        # public extractor still rejects it at manifest SHA; this proves the
        # instruction/operand comparison independently rejects the mutation.
        resealed = temp / "resealed-exports"
        shutil.copytree(bad_exports, resealed)
        metadata_path = resealed / "manifest.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["files"]["0062c400.asm"] = {"bytes": len(changed_asm),
                                                 "sha256": hashlib.sha256(changed_asm).hexdigest()}
        metadata_path.write_text(json.dumps(metadata, indent=2)+"\n", encoding="utf-8", newline="\n")
        resealed_sha = digest(metadata_path)
        diagnostic = ("import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                      "import extract_match_status_23 as x;x.MANIFEST=sys.argv[2];"
                      "x.extract(Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]))")
        for mode, flag in (("normal", []), ("optimized", ["-O"])):
            failure = run([sys.executable, *flag, "-c", diagnostic, str(scripts), resealed_sha,
                           str(args.binary), str(resealed), str(args.preflight)], False)
            need("native/original operand mismatch at 0062c400" in failure.stderr,
                 "resealed native mutation did not reach operand comparator")
            negatives["resealed_native_operand_"+mode] = {"rejected": True,
                                                            "reason": "original/native operand mismatch"}
        good = run([str(args.node), str(args.checker), str(args.oracle)], True)
        need('"checked_cases":43' in good.stdout, "Node checker did not cover 43 cases")
        bad = run([str(args.node), str(args.checker), str(args.oracle), "--mutate-low-byte"], False)
        need("register mismatch" in bad.stderr, "TS mutation not detected")
        negatives["changed_typescript_result"] = {"rejected": True, "reason": "register mismatch"}
        tampered = temp / "tampered-oracle.json"
        raw = args.oracle.read_bytes()
        tampered.write_bytes(raw[:-2])
        bad = run([str(args.node), str(args.checker), str(tampered)], False)
        need("oracle SHA-256 mismatch" in bad.stderr, "oracle mutation not detected")
        negatives["tampered_oracle"] = {"rejected": True, "reason": "oracle SHA-256 mismatch"}
        return {"work_unit": "R23-A", "normal_optimized_sites_identical": True,
                "normal_optimized_oracle_identical": True, "sites_sha256": digest(args.sites),
                "oracle_sha256": digest(args.oracle), "negative_checks": negatives,
                "scope": "original-instruction no-callee guard domain; other body paths static only"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--sites", type=Path, required=True)
    p.add_argument("--oracle", type=Path, required=True)
    p.add_argument("--checker", type=Path, required=True)
    p.add_argument("--node", type=Path, required=True)
    p.add_argument("--scratch", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.scratch.mkdir(parents=True, exist_ok=True)
    result = check(args)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
