#!/usr/bin/env python3
"""Reproduce optimized/integrity and mutation gates for R27-A."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from extract_iterator_helpers_27 import extract, sha

ROOT = Path(__file__).resolve().parents[1]


def command(argv, success):
    p = subprocess.run([str(a) for a in argv], cwd=ROOT, capture_output=True, text=True)
    if (p.returncode == 0) != success:
        raise ValueError(f"unexpected command result {p.returncode}: {argv}: {p.stdout} {p.stderr}")
    return p


def load_extractor():
    path = ROOT / "scripts/extract_iterator_helpers_27.py"
    spec = importlib.util.spec_from_file_location("sealed_iterator_extractor", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(exe, exports, preflight, node):
    original_sites = (ROOT / "evidence/iterator-helpers-27-sites.json").read_bytes()
    original_oracle = (ROOT / "evidence/iterator-helpers-27-oracle.json.gz").read_bytes()
    if json.loads(original_sites) != extract(exe, exports, preflight):
        raise ValueError("retained sites differ from current extraction")
    checks = []
    with tempfile.TemporaryDirectory(prefix="iterator27-") as temp:
        temp = Path(temp)
        for optimized in (False, True):
            prefix = [sys.executable] + (["-O"] if optimized else [])
            site_out = temp / ("sites-o.json" if optimized else "sites.json")
            oracle_out = temp / ("oracle-o.gz" if optimized else "oracle.gz")
            command(prefix + [ROOT / "scripts/extract_iterator_helpers_27.py", exe, exports, preflight, site_out], True)
            command(prefix + [ROOT / "scripts/emulate_iterator_helpers_27.py", exe, exports, preflight, oracle_out], True)
            if site_out.read_bytes() != original_sites or oracle_out.read_bytes() != original_oracle:
                raise ValueError("normal/-O evidence diverges")
            checks.append("normal/-O exact sites and oracle" if optimized else "normal exact sites and oracle")
        corrupted = bytearray(exe.read_bytes())
        corrupted[0x28d1b9 + 2] ^= 1
        bad_exe = temp / "bad.exe"
        bad_exe.write_bytes(corrupted)
        command([sys.executable, ROOT / "scripts/extract_iterator_helpers_27.py", bad_exe, exports, preflight, temp / "bad.json"], False)
        command([sys.executable, "-O", ROOT / "scripts/emulate_iterator_helpers_27.py", bad_exe, exports, preflight, temp / "bad.gz"], False)
        checks.append("mutated specimen rejected normal and -O")
        bad_exports = temp / "exports"
        shutil.copytree(exports, bad_exports)
        with (bad_exports / "0068d1b0.asm").open("ab") as handle:
            handle.write(b"\n")
        command([sys.executable, ROOT / "scripts/extract_iterator_helpers_27.py", exe, bad_exports, preflight, temp / "bad-native.json"], False)
        checks.append("mutated native export rejected")
        bad_manifest = temp / "bad-manifest"
        shutil.copytree(exports, bad_manifest)
        with (bad_manifest / "manifest.json").open("ab") as handle:
            handle.write(b"\n")
        command([sys.executable, "-O", ROOT / "scripts/extract_iterator_helpers_27.py", exe, bad_manifest, preflight, temp / "bad-manifest.json"], False)
        checks.append("mutated manifest rejected under -O")
        bad_preflight = temp / "bad-preflight.json"
        bad_preflight.write_bytes(preflight.read_bytes() + b"\n")
        command([sys.executable, ROOT / "scripts/extract_iterator_helpers_27.py", exe, exports, bad_preflight, temp / "bad-preflight-out.json"], False)
        checks.append("mutated preflight rejected")
        # Reseal native metadata deliberately to exercise the actual instruction/operand comparator.
        sealed_exports = temp / "sealed-exports"
        shutil.copytree(exports, sealed_exports)
        asm = sealed_exports / "0068d1b0.asm"
        asm.write_text(asm.read_text().replace("[EDX + 0x6]", "[EDX + 0xa]"), encoding="utf-8")
        manifest = json.loads((sealed_exports / "manifest.json").read_text())
        manifest["files"][asm.name] = {"bytes": asm.stat().st_size, "sha256": sha(asm.read_bytes())}
        (sealed_exports / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        module = load_extractor()
        module.MANIFEST = sha((sealed_exports / "manifest.json").read_bytes())
        try:
            module.extract(exe, sealed_exports, preflight)
        except ValueError as error:
            if "complete original/native instruction mismatch" not in str(error):
                raise
        else:
            raise ValueError("resealed wrong link operand accepted")
        checks.append("resealed native link-offset operand rejected by PE/native comparator")
        # Independently reseal the opposite direction: altered PE operand, authentic native listing.
        sealed_exe = temp / "sealed.exe"
        altered = bytearray(exe.read_bytes())
        altered[0x28d1b9 + 2] = 0x0a
        sealed_exe.write_bytes(altered)
        sealed_preflight = temp / "sealed-preflight.json"
        old = json.loads(preflight.read_text())
        old["sha256"] = sha(altered)
        sealed_preflight.write_text(json.dumps(old), encoding="utf-8")
        sealed_manifest = temp / "sealed-manifest"
        shutil.copytree(exports, sealed_manifest)
        m = json.loads((sealed_manifest / "manifest.json").read_text())
        m["specimen_sha256"] = sha(altered)
        m["preflight_sha256"] = sha(sealed_preflight.read_bytes())
        (sealed_manifest / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
        module = load_extractor()
        module.PINNED = sha(altered)
        module.PREFLIGHT = sha(sealed_preflight.read_bytes())
        module.MANIFEST = sha((sealed_manifest / "manifest.json").read_bytes())
        try:
            module.extract(sealed_exe, sealed_manifest, sealed_preflight)
        except ValueError as error:
            if "complete original/native instruction mismatch" not in str(error):
                raise
        else:
            raise ValueError("resealed wrong PE link operand accepted")
        checks.append("resealed PE link-offset operand rejected by PE/native comparator")
        oracle_bad = temp / "oracle-bad.gz"
        oracle_bad.write_bytes(original_oracle[:-1] + bytes([original_oracle[-1] ^ 1]))
        command([node, ROOT / "reconstruction/check-iterator-helpers-27.ts", oracle_bad], False)
        checks.append("mutated retained oracle rejected")
        for mode in ("--mutate-result", "--mutate-effect"):
            command([node, ROOT / "reconstruction/check-iterator-helpers-27.ts", ROOT / "evidence/iterator-helpers-27-oracle.json.gz", mode], False)
            checks.append(mode + " rejected")
        command([node, ROOT / "reconstruction/check-iterator-helpers-27.ts"], True)
    return {"work_unit": "R27-A", "specimen_sha256":
            "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86",
            "checks": checks, "count": len(checks), "status": "passed"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "node", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    a.output.write_text(json.dumps(main(a.exe.resolve(), a.exports.resolve(), a.preflight.resolve(), a.node.resolve()), indent=2) + "\n", encoding="utf-8", newline="\n")
