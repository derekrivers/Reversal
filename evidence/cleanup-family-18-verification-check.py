#!/usr/bin/env python3
"""Reproduce the R20-V1 checks; private inputs and mutations stay outside Git."""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

from capstone import __version__ as capstone_version


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    ap = argparse.ArgumentParser()
    for name in ("binary", "exports", "semantic", "receipt"):
        ap.add_argument(f"--{name}", required=True, type=Path)
    args = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/extract_cleanup_family_18.py"
    spec = importlib.util.spec_from_file_location("cleanup_census", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = args.binary.read_bytes()
    require(module.sha(data) == module.SPECIMEN, "wrong test specimen")
    read = module.pe_reader(data)
    md = module.Cs(module.CS_ARCH_X86, module.CS_MODE_32)
    retained = [root / f"evidence/cleanup-family-18-{name}" for name in ("summary.json", "rows.jsonl")]
    before = [module.sha(p.read_bytes()) for p in retained]
    cases = []
    with tempfile.TemporaryDirectory(prefix="cleanup-family-18-") as temporary:
        temp = Path(temporary)
        summary, rows = temp / "summary.json", temp / "rows.jsonl"
        command = [str(script), "--binary", str(args.binary.resolve()),
                   "--atlas", str(root / "evidence/code-atlas/functions.jsonl"),
                   "--exports", str(args.exports.resolve()), "--semantic", str(args.semantic.resolve()),
                   "--summary", str(summary), "--rows", str(rows)]
        positive = subprocess.run([sys.executable, *command], capture_output=True, text=True)
        require(positive.returncode == 0, positive.stderr)
        require([module.sha(p.read_bytes()) for p in (summary, rows)] == before,
                "repeat differs from retained census")

        # Exercise the operand checker independently of the manifest hash gate.
        mutations = {
            "field_displacement": ("00410840", lambda text: text.replace("0xa7", "0xa8", 1)),
            "memory_width": ("00410840", lambda text: re.sub(r"\bword ptr", "dword ptr", text, count=1)),
            "register": ("00410840", lambda text: text.replace("MOV ESI,ECX", "MOV ESI,EAX", 1)),
            "segment": ("00410840", lambda text: text.replace("FS:", "GS:", 1)),
            "index_scale": ("00410840", lambda text: text.replace("*0x4", "*0x8", 1)),
            "direct_callee": ("00410840", lambda text: re.sub(r"(CALL )0x([0-9a-f]+)", lambda m: m[1] + hex(int(m[2], 16) + 1), text, count=1)),
            "local_branch_target": ("00410840", lambda text: re.sub(r"(JZ )0x([0-9a-f]+)", lambda m: m[1] + hex(int(m[2], 16) + 1), text, count=1)),
            "signed_immediate": ("00410840", lambda text: text.replace("PUSH -0x1", "PUSH -0x2", 1)),
            "metadata_literal": ("00410840", lambda text: text.replace("0x9539a8", "0x9539a9", 1)),
            "receiver_literal": ("00410840", lambda text: text.replace("0x9676c8", "0x9676c9", 1)),
            "indirect_callee": ("00401220", lambda text: text.replace("CALL dword ptr [EDX]", "CALL dword ptr [ECX]", 1)),
            "instruction_count": ("00410840", lambda text: text.split("\n", 1)[1]),
            "instruction_address": ("00410840", lambda text: text.replace("00410840", "00410841", 1)),
            "unsupported_operand": ("00410840", lambda text: text.replace("FS:[0x0]", "FS:[unknown]", 1)),
        }
        for name, (address, mutate) in mutations.items():
            original = (args.exports / f"{address}.asm").read_text(encoding="utf-8")
            changed = mutate(original)
            require(changed != original, f"inactive mutation: {name}")
            sample = temp / "mutated.asm"
            sample.write_text(changed, encoding="utf-8")
            size = next(v[1] for v in module.TEMPLATES.values() if v[0] == address)
            _, instructions = module.decode(md, read, int(address, 16), size)
            try:
                module.check_ghidra_sample(sample, instructions)
            except (AssertionError, ValueError):
                cases.append(name)
            else:
                raise RuntimeError(f"accepted mutated native sample: {name}")

        # Rehash a disposable export copy solely within this test harness so the
        # full main() run reaches the operand gate after manifest verification.
        exports = temp / "exports"
        shutil.copytree(args.exports, exports)
        sample = exports / "00410840.asm"
        sample.write_text(mutations["field_displacement"][1](sample.read_text(encoding="utf-8")), encoding="utf-8")
        manifest = json.loads((exports / "manifest.json").read_text(encoding="utf-8"))
        payload = sample.read_bytes()
        manifest["files"][sample.name] = {"bytes": len(payload), "sha256": module.sha(payload)}
        (exports / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        negative_command = command.copy()
        negative_command[negative_command.index("--exports") + 1] = str(exports)
        sentinels = [p.read_bytes() for p in (summary, rows)]
        with patch.object(module, "EXPORT_MANIFEST", module.sha((exports / "manifest.json").read_bytes())), patch.object(sys, "argv", negative_command):
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    module.main()
            except AssertionError as error:
                require("native instruction mismatch" in str(error), "negative case failed before operand comparison")
            else:
                raise RuntimeError("full extractor accepted changed operand")
        require([p.read_bytes() for p in (summary, rows)] == sentinels, "negative case wrote output")

        # Missing input paths prove optimized mode refuses before evidence I/O.
        optimized_command = command.copy()
        for name in ("binary", "atlas", "exports", "semantic"):
            optimized_command[optimized_command.index(f"--{name}") + 1] = str(temp / "missing" / name)
        optimized = subprocess.run([sys.executable, "-O", *optimized_command], capture_output=True, text=True)
        require(optimized.returncode != 0 and "refuses optimized Python" in optimized.stderr,
                "optimized mode did not refuse immediately")
        require("FileNotFoundError" not in optimized.stderr, "optimized mode read evidence")
        require([p.read_bytes() for p in (summary, rows)] == sentinels, "optimized mode wrote output")
    require([module.sha(p.read_bytes()) for p in retained] == before, "retained census changed during checks")
    receipt = {
        "specimen_sha256": module.SPECIMEN, "capstone": capstone_version,
        "sample_manifest_sha256": module.EXPORT_MANIFEST,
        "historical_semantic_commit": module.SEMANTIC_COMMIT,
        "historical_semantic_sha256": module.SEMANTIC_SHA256,
        "positive_repeat_matches_retained": True, "samples": 4, "instructions": 217,
        "rejected_native_sample_mutations": cases,
        "full_extractor_changed_operand_rejected": True,
        "full_extractor_negative_manifest": "test harness rehash of disposable copy; production pin unchanged",
        "optimized_mode": "refused with missing evidence paths before evidence I/O",
        "negative_outputs_unchanged": True, "retained_outputs_unchanged": True,
        "summary_sha256": before[0], "rows_sha256": before[1],
        "limits": "static instruction comparison; no execution or transitive callee equivalence",
    }
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
