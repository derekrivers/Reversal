#!/usr/bin/env python3
"""Check R29-C provenance and independently resealed native instruction mutations."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import tempfile


def need(ok, message):
    if not ok:
        raise ValueError(message)


def reject(label, expected, work):
    try:
        work()
    except ValueError as exc:
        need(expected in str(exc), label + ": wrong gate: " + str(exc))
        return {"probe": label, "rejected": True, "gate": expected}
    raise ValueError(label + ": mutation accepted")


def replace_once(path, old, new):
    raw = path.read_bytes()
    need(raw.count(old) == 1, "mutation site not unique: " + str(path))
    path.write_bytes(raw.replace(old, new))


def copy_disposable_exports(source, target):
    """Make only the temporary copy writable; preserve the private source."""
    shutil.copytree(source, target)
    for path in target.rglob("*"):
        path.chmod(path.stat().st_mode | stat.S_IWRITE)
    target.chmod(target.stat().st_mode | stat.S_IWRITE)


def run(module, exe, exports, preflight):
    module.extract(exe, exports, preflight)
    receipts = []
    with tempfile.TemporaryDirectory(prefix="r29c-negative-") as temp:
        base = Path(temp)
        specimen = base / "changed.exe"
        shutil.copyfile(exe, specimen)
        with specimen.open("r+b") as stream:
            stream.seek(0x28d2e0)
            value = stream.read(1)
            stream.seek(0x28d2e0)
            stream.write(bytes([value[0] ^ 1]))
        receipts.append(reject("PE byte", "pinned specimen mismatch",
                               lambda: module.extract(specimen, exports, preflight)))
        copied = base / "exports"
        copy_disposable_exports(exports, copied)
        replace_once(copied / "0068d2e0.asm", b"[ECX + 0xa]", b"[ECX + 0x6]")
        receipts.append(reject("unsealed native operand", "native export mismatch",
                               lambda: module.extract(exe, copied, preflight)))
        shutil.rmtree(copied)
        copy_disposable_exports(exports, copied)
        replace_once(copied / "manifest.json", b'"bytes": 171', b'"bytes": 172')
        receipts.append(reject("manifest", "manifest/preflight SHA-256 mismatch",
                               lambda: module.extract(exe, copied, preflight)))
        old_copy = base / "preflight.json"
        shutil.copyfile(preflight, old_copy)
        replace_once(old_copy, b'"body_addresses": 13', b'"body_addresses": 14')
        receipts.append(reject("preflight", "manifest/preflight SHA-256 mismatch",
                               lambda: module.extract(exe, exports, old_copy)))
        for label, filename, old, new in (
            ("getter pointer operand", "0068d2e0.asm", b"[ECX + 0xa]", b"[ECX + 0x6]"),
            ("remove-node return cleanup", "0068d280.asm", b"RET 0x4", b"RET 0x8"),
            ("clear release target", "0068d080.asm", b"CALL 0x00944c94", b"CALL 0x00944c95"),
            ("copy append target", "0068d2f0.asm", b"CALL 0x0068d0d0", b"CALL 0x0068d0d1"),
            ("copy pointer operand", "0068d2f0.asm", b"0068d341  MOV dword ptr [EDI + 0xa],ECX", b"0068d341  MOV dword ptr [EDI + 0x6],ECX"),
        ):
            shutil.rmtree(copied)
            copy_disposable_exports(exports, copied)
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
                receipts.append(reject(label, "PE/native opcode or operand mismatch",
                                       lambda: module.extract(exe, copied, preflight)))
            finally:
                module.MANIFEST = original
        shutil.rmtree(copied)
        copy_disposable_exports(exports, copied)
        old = json.loads(preflight.read_bytes())
        for site in old["sites"]:
            if site["address"] == "0068d2e0":
                site["function_name"] = "FUN_0068d2e1"
        old_copy.write_text(json.dumps(old, indent=2) + "\n", encoding="utf-8", newline="\n")
        manifest_path = copied / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["preflight_sha256"] = module.sha(old_copy.read_bytes())
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
        orig_manifest, orig_preflight = module.MANIFEST, module.PREFLIGHT
        try:
            module.MANIFEST = module.sha(manifest_path.read_bytes())
            module.PREFLIGHT = module.sha(old_copy.read_bytes())
            receipts.append(reject("exact-old name", "exact-old native name/body mismatch",
                                   lambda: module.extract(exe, copied, old_copy)))
        finally:
            module.MANIFEST, module.PREFLIGHT = orig_manifest, orig_preflight
    return {"schema_version": 1, "unit": "R29-C", "specimen_sha256": module.SPECIMEN,
            "optimized_integrity": "explicit gates; no assert", "probes": receipts}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    spec = importlib.util.spec_from_file_location("r29c_extract", Path(__file__).with_name("extract_collection_continuation_29.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = run(module, a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("R29-C negative probes:", len(result["probes"]))
