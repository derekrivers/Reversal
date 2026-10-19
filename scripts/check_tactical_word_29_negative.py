#!/usr/bin/env python3
"""Regenerate R29-B evidence and test sealed-integrity and model mutations."""
import argparse
import gzip
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from extract_tactical_word_29 import extract, sha
from check_tactical_word_29_privacy import scan_authored

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "evidence/tactical-word-29-sites.json"
ORACLE = ROOT / "evidence/tactical-word-29-oracle.json.gz"


def command(args, success):
    result = subprocess.run([str(x) for x in args], cwd=ROOT, capture_output=True, text=True)
    if (result.returncode == 0) != success:
        raise ValueError(f"unexpected status {result.returncode}: {args}: {result.stdout} {result.stderr}")
    return result


def module_copy():
    spec = importlib.util.spec_from_file_location("sealed_tactical_extractor", ROOT / "scripts/extract_tactical_word_29.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(exe, exports, preflight, node):
    original_sites = SITE.read_bytes()
    original_oracle = ORACLE.read_bytes()
    if json.loads(original_sites) != extract(exe, exports, preflight):
        raise ValueError("retained site evidence differs from extraction")
    checks = []
    with tempfile.TemporaryDirectory(prefix="tactical29-") as path:
        temp = Path(path)
        for optimized in (False, True):
            python = [sys.executable] + (["-O"] if optimized else [])
            sites_out = temp / ("sites-o.json" if optimized else "sites.json")
            oracle_out = temp / ("oracle-o.gz" if optimized else "oracle.gz")
            command(python + [ROOT / "scripts/extract_tactical_word_29.py", exe, exports, preflight, sites_out], True)
            command(python + [ROOT / "scripts/emulate_tactical_word_29.py", exe, exports, preflight, oracle_out], True)
            if sites_out.read_bytes() != original_sites or oracle_out.read_bytes() != original_oracle:
                raise ValueError("normal/-O evidence diverges")
            checks.append("optimized Python exact regeneration" if optimized else "normal Python exact regeneration")
        damaged_exe = temp / "damaged.exe"
        raw = bytearray(exe.read_bytes())
        raw[0x2c3908] ^= 1
        damaged_exe.write_bytes(raw)
        command([sys.executable, ROOT / "scripts/extract_tactical_word_29.py", damaged_exe, exports, preflight, temp / "out.json"], False)
        checks.append("changed PE rejected")
        damaged_exports = temp / "exports"
        shutil.copytree(exports, damaged_exports)
        asm = damaged_exports / "006c38f0.asm"
        asm.write_text(asm.read_text().replace("0x8ec4", "0x8ec8"))
        command([sys.executable, ROOT / "scripts/extract_tactical_word_29.py", exe, damaged_exports, preflight, temp / "out.json"], False)
        checks.append("changed native export rejected")
        shutil.copy2(exports / "006c38f0.asm", asm)
        manifest = damaged_exports / "manifest.json"
        manifest.write_bytes(manifest.read_bytes()+b" ")
        command([sys.executable, ROOT / "scripts/extract_tactical_word_29.py", exe, damaged_exports, preflight, temp / "out.json"], False)
        checks.append("changed manifest rejected")
        altered_preflight = temp / "preflight.json"
        altered_preflight.write_bytes(preflight.read_bytes()+b" ")
        command([sys.executable, ROOT / "scripts/extract_tactical_word_29.py", exe, exports, altered_preflight, temp / "out.json"], False)
        checks.append("changed preflight rejected")
        # Reseal a wrong native operand so that the instruction comparator, rather
        # than only the outer hash, must reject it.
        asm.write_text((exports / "006c38f0.asm").read_text().replace("0x8ec4", "0x8ec8"))
        payload = json.loads((exports / "manifest.json").read_text())
        payload["files"]["006c38f0.asm"]["bytes"] = len(asm.read_bytes())
        payload["files"]["006c38f0.asm"]["sha256"] = sha(asm.read_bytes())
        manifest.write_text(json.dumps(payload))
        module = module_copy()
        module.MANIFEST = sha(manifest.read_bytes())
        try:
            module.extract(exe, damaged_exports, preflight)
        except ValueError as error:
            if "complete original/native instruction mismatch" not in str(error):
                raise
        else:
            raise ValueError("resealed wrong native operand accepted")
        checks.append("resealed wrong native operand rejected by instruction comparator")
        damaged_oracle = temp / "oracle.gz"
        damaged_oracle.write_bytes(original_oracle[:-1]+bytes([original_oracle[-1]^1]))
        command([node, ROOT / "reconstruction/check-tactical-word-29.ts", damaged_oracle], False)
        checks.append("changed oracle rejected")
        for mutation in ("--mutate-result", "--mutate-effect"):
            command([node, ROOT / "reconstruction/check-tactical-word-29.ts", ORACLE, mutation], False)
            checks.append(mutation + " rejected")
        specimen = exe.read_bytes()
        bodies = [specimen[int(f["file_offset"], 16):int(f["file_offset"], 16) + 42]
                  for f in json.loads(original_sites)["functions"]]
        for label, injected in (("raw", bodies[0][:16]), ("hex", bodies[0][:16].hex().encode())):
            probe = temp / ("private-" + label + ".gz")
            probe.write_bytes(gzip.compress(b"synthetic-prefix:" + injected, mtime=0))
            try:
                scan_authored(probe, bodies)
            except ValueError as error:
                if "original PE fragment" not in str(error):
                    raise
            else:
                raise ValueError("expanded gzip " + label + " private fragment accepted")
            checks.append("expanded gzip " + label + " fragment rejected")
        oversized = temp / "oversized.gz"
        oversized.write_bytes(gzip.compress(b"X" * 33, mtime=0))
        try:
            scan_authored(oversized, bodies, max_expanded_bytes=32)
        except ValueError as error:
            if "privacy scan limit" not in str(error):
                raise
        else:
            raise ValueError("oversized expanded gzip accepted")
        checks.append("expanded gzip size limit enforced")
        command([node, ROOT / "reconstruction/check-tactical-word-29.ts"], True)
    return {"work_unit": "R29-B", "specimen_sha256": json.loads(original_sites)["specimen_sha256"],
            "status": "passed", "count": len(checks), "checks": checks}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "node", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    a.output.write_text(json.dumps(run(a.exe.resolve(), a.exports.resolve(), a.preflight.resolve(), a.node.resolve()), indent=2)+"\n", encoding="utf-8", newline="\n")
