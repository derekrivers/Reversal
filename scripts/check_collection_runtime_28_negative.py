#!/usr/bin/env python3
"""Exercise R28-C provenance, operand, call-target and old-library gates."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile


def need(ok, message):
    if not ok:
        raise ValueError(message)


def expect(label, expected, work):
    try:
        work()
    except ValueError as exc:
        need(expected in str(exc), label + ": wrong rejection: " + str(exc))
        return {"probe": label, "rejected": True, "gate": expected}
    raise ValueError(label + ": tampered input was accepted")


def replace_once(path, old, new):
    raw = path.read_bytes()
    need(raw.count(old) == 1, "mutation site not unique: " + str(path))
    path.write_bytes(raw.replace(old, new))


def run(module, exe, exports, preflight):
    module.extract(exe, exports, preflight)
    receipts = []
    with tempfile.TemporaryDirectory(prefix="r28c-negative-") as temp:
        base = Path(temp)
        specimen = base / "mutated.exe"
        shutil.copyfile(exe, specimen)
        with specimen.open("r+b") as stream:
            stream.seek(0x28cfc3)
            byte = stream.read(1)
            stream.seek(0x28cfc3)
            stream.write(bytes([byte[0] ^ 1]))
        receipts.append(expect("PE byte mutation", "pinned specimen mismatch",
                               lambda: module.extract(specimen, exports, preflight)))

        copied = base / "exports"
        shutil.copytree(exports, copied)
        replace_once(copied / "0068cfc0.asm", b"MOV DI,word ptr [ESP + 0x14]", b"MOV DI,word ptr [ESP + 0x18]")
        receipts.append(expect("unsealed native operand mutation", "native export mismatch",
                               lambda: module.extract(exe, copied, preflight)))

        shutil.rmtree(copied)
        shutil.copytree(exports, copied)
        replace_once(copied / "manifest.json", b'"bytes": 711', b'"bytes": 712')
        receipts.append(expect("manifest mutation", "manifest/preflight SHA-256 mismatch",
                               lambda: module.extract(exe, copied, preflight)))

        old_copy = base / "preflight.json"
        shutil.copyfile(preflight, old_copy)
        replace_once(old_copy, b'"body_addresses": 66', b'"body_addresses": 67')
        receipts.append(expect("preflight mutation", "manifest/preflight SHA-256 mismatch",
                               lambda: module.extract(exe, exports, old_copy)))

        for label, filename, old, new in (
            ("resealed constructor operand mutation", "0068cfc0.asm", b"MOV DI,word ptr [ESP + 0x14]",
             b"MOV DI,word ptr [ESP + 0x18]"),
            ("resealed operator-new callee mutation", "00944cf1.asm", b"CALL 0x00944e58",
             b"CALL 0x00944e59"),
            ("resealed caller node-size mutation", "0068d0d0.asm", b"0068d0e9  PUSH 0xe",
             b"0068d0e9  PUSH 0xf"),
        ):
            shutil.rmtree(copied)
            shutil.copytree(exports, copied)
            target = copied / filename
            replace_once(target, old, new)
            manifest_path = copied / "manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["files"][filename] = {"bytes": target.stat().st_size,
                                           "sha256": module.sha(target.read_bytes())}
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
            original = module.MANIFEST
            try:
                module.MANIFEST = module.sha(manifest_path.read_bytes())
                receipts.append(expect(label, "PE/native opcode or operand mismatch",
                                       lambda: module.extract(exe, copied, preflight)))
            finally:
                module.MANIFEST = original

        shutil.rmtree(copied)
        shutil.copytree(exports, copied)
        old_copy.write_text(preflight.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        old = json.loads(old_copy.read_bytes())
        for site in old["sites"]:
            if site["address"] == "00944cf1":
                site["function_comment"] += " altered"
        old_copy.write_text(json.dumps(old, indent=2) + "\n", encoding="utf-8", newline="\n")
        manifest_path = copied / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["preflight_sha256"] = module.sha(old_copy.read_bytes())
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
        original_manifest, original_preflight = module.MANIFEST, module.PREFLIGHT
        try:
            module.MANIFEST = module.sha(manifest_path.read_bytes())
            module.PREFLIGHT = module.sha(old_copy.read_bytes())
            receipts.append(expect("resealed library comment mutation", "existing CRT library comment mismatch",
                                   lambda: module.extract(exe, copied, old_copy)))
        finally:
            module.MANIFEST, module.PREFLIGHT = original_manifest, original_preflight
    return {"schema_version": 1, "unit": "R28-C", "specimen_sha256": module.SPECIMEN,
            "normal_and_optimized_integrity": "explicit gates, no assert", "probes": receipts}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    source = Path(__file__).with_name("extract_collection_runtime_28.py")
    spec = importlib.util.spec_from_file_location("r28c_extract", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = run(module, a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("R28-C negative probes:", len(result["probes"]))
