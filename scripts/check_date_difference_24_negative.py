#!/usr/bin/env python3
"""Reproduce R24-B normal/-O equality and integrity/mutation rejection."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def invoke(argv, expected_success):
    result = subprocess.run(argv, capture_output=True, text=True)
    need((result.returncode == 0) == expected_success,
         f"unexpected exit {result.returncode}: {' '.join(map(str, argv))}: {result.stderr[-1500:]}")
    return result


def run(args):
    here = Path(__file__).resolve().parent.parent
    extractor = here / "scripts/extract_date_difference_24.py"
    emulator = here / "scripts/emulate_date_difference_24.py"
    checker = here / "reconstruction/check-date-difference.ts"
    sites = here / "evidence/date-difference-24-sites.json"
    oracle = here / "evidence/date-difference-24-oracle.json"
    receipt = {"work_unit": "R24-B", "python": sys.version.split()[0],
               "sites_sha256": sha(sites.read_bytes()), "oracle_sha256": sha(oracle.read_bytes()),
               "checks": []}
    with tempfile.TemporaryDirectory(prefix="date-24-", dir=args.scratch) as scratch:
        tmp = Path(scratch)
        for script, expected in ((extractor, sites), (emulator, oracle)):
            normal, optimized = tmp / "normal.json", tmp / "optimized.json"
            base = [str(args.binary), "--exports", str(args.exports), "--preflight",
                    str(args.preflight)]
            invoke([sys.executable, str(script), *base, "--output", str(normal)], True)
            invoke([sys.executable, "-O", str(script), *base, "--output", str(optimized)], True)
            need(normal.read_bytes() == optimized.read_bytes() == expected.read_bytes(),
                 "normal/-O/evidence byte mismatch")
            receipt["checks"].append(script.name + ": normal and -O byte identical to retained evidence")
        changed_binary = tmp / "cm0102-mutated.exe"
        raw = bytearray(args.binary.read_bytes())
        raw[0x14cc30] ^= 1
        changed_binary.write_bytes(raw)
        for mode in ([], ["-O"]):
            invoke([sys.executable, *mode, str(extractor), str(changed_binary),
                    "--exports", str(args.exports), "--preflight", str(args.preflight),
                    "--output", str(tmp / "bad.json")], False)
        receipt["checks"].append("changed PE rejected before output in normal and -O")
        changed_exports = tmp / "exports"
        shutil.copytree(args.exports, changed_exports)
        asm = changed_exports / "0054cc30.asm"
        original = asm.read_text()
        need("PUSH -0x1" in original, "native mutation target missing")
        asm.write_text(original.replace("PUSH -0x1", "PUSH -0x2", 1))
        for mode in ([], ["-O"]):
            invoke([sys.executable, *mode, str(extractor), str(args.binary),
                    "--exports", str(changed_exports), "--preflight", str(args.preflight),
                    "--output", str(tmp / "bad.json")], False)
        receipt["checks"].append("changed native export rejected by hash in normal and -O")
        manifest_path = changed_exports / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        asm_raw = asm.read_bytes()
        manifest["files"]["0054cc30.asm"] = {"bytes": len(asm_raw), "sha256": sha(asm_raw)}
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        new_manifest_sha = sha(manifest_path.read_bytes())
        source = ("import sys;sys.path.insert(0," + repr(str(here / "scripts")) + ");"
                  "import extract_date_difference_24 as x;"
                  "from pathlib import Path;"
                  "x.MANIFEST=" + repr(new_manifest_sha) + ";"
                  "x.extract(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))")
        for mode in ([], ["-O"]):
            result = invoke([sys.executable, *mode, "-c", source, str(args.binary),
                             str(changed_exports), str(args.preflight)], False)
            need("native/original operand mismatch at 0054cc30" in result.stderr,
                 "resealed native mutation did not reach operand comparator")
        receipt["checks"].append("resealed native operand rejected by independent PE comparison in normal and -O")
        width_exports = tmp / "exports-width"
        shutil.copytree(args.exports, width_exports)
        width_asm = width_exports / "0054cc30.asm"
        width_text = width_asm.read_text()
        old, new = "MOV dword ptr FS:[0x0],ESP", "MOV word ptr FS:[0x0],ESP"
        need(old in width_text, "native width mutation target missing")
        width_asm.write_text(width_text.replace(old, new, 1))
        width_manifest_path = width_exports / "manifest.json"
        width_manifest = json.loads(width_manifest_path.read_text())
        width_raw = width_asm.read_bytes()
        width_manifest["files"]["0054cc30.asm"] = {"bytes": len(width_raw), "sha256": sha(width_raw)}
        width_manifest_path.write_text(json.dumps(width_manifest, indent=2) + "\n", encoding="utf-8")
        width_manifest_sha = sha(width_manifest_path.read_bytes())
        width_source = ("import sys;sys.path.insert(0," + repr(str(here / "scripts")) + ");"
                        "import extract_date_difference_24 as x;from pathlib import Path;"
                        "x.MANIFEST=" + repr(width_manifest_sha) + ";"
                        "x.extract(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))")
        for mode in ([], ["-O"]):
            result = invoke([sys.executable, *mode, "-c", width_source, str(args.binary),
                             str(width_exports), str(args.preflight)], False)
            need("native width mismatch at 0054cc3e" in result.stderr,
                 "resealed native width mutation did not reach exact-width comparator")
        receipt["checks"].append("resealed native DWORD-to-WORD operand rejected by exact width comparison in normal and -O")
        invoke([str(args.node), str(checker), str(oracle)], True)
        invoke([str(args.node), str(checker), str(oracle), "--mutate-result"], False)
        mutated_ts = tmp / "mutated-ts"
        mutated_ts.mkdir()
        shutil.copy2(checker, mutated_ts / checker.name)
        implementation = here / "reconstruction/date-difference.ts"
        implementation_text = implementation.read_text()
        ordinal_write = "  memory.write16(0x00ae2428, days & 0xffff);\n"
        year_read = "  word(yearAgain);\n"
        need(implementation_text.count(ordinal_write) == 1 and implementation_text.count(year_read) == 1,
             "TypeScript order mutation target missing")
        altered = implementation_text.replace(ordinal_write, "", 1).replace(
            year_read, year_read + ordinal_write, 1)
        (mutated_ts / implementation.name).write_text(altered, encoding="utf-8")
        order_result = invoke([str(args.node), str(mutated_ts / checker.name), str(oracle)], False)
        need("memory mismatch case 0" in order_result.stderr,
             "reordered TypeScript implementation not rejected by merged event trace")
        changed_oracle = tmp / "mutated-oracle.json"
        oracle_bytes = oracle.read_bytes()
        changed_oracle.write_bytes(oracle_bytes.replace(b'"function_cases": 95', b'"function_cases": 96', 1))
        need(changed_oracle.read_bytes() != oracle_bytes, "oracle mutation failed")
        invoke([str(args.node), str(checker), str(changed_oracle)], False)
        receipt["checks"].append("TypeScript result, read-before-write implementation mutation, and oracle mutations rejected")
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--node", type=Path, required=True)
    p.add_argument("--scratch", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    run(p.parse_args())
