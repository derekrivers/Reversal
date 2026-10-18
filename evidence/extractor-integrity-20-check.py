#!/usr/bin/env python3
"""Check fail-closed extractor entry points; private inputs are read-only.

Run with Capstone 5.0.7 and the pinned binary, R17 exports and preflight.
Only temporary outputs and this compact receipt are written; no private paths,
subprocess traces, source bytes or native assembly are retained in the receipt.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
REFUSAL = "Integrity checks require assertions; rerun without Python optimization (-O/-OO)."
ALIAS_REFUSAL = "receipt must not alias a private input or reside in the private export directory"
EXCLUDED = "extract_cleanup_family_18.py"  # R20-V1 owns this repair.
ROOT = Path(__file__).resolve().parents[1]

# Compile source before the hook; every subsequent open/import is forbidden.
# Preload __future__: Python requires its declarations before an entry guard.
# This proves optimized execution stops before dependencies or evidence I/O,
# even when valid private input paths and writable output paths are supplied.
PROBE = r'''
import __future__
import sys
source = sys.argv[1]
with open(source, encoding="utf-8") as stream:
    code = compile(stream.read(), source, "exec")
sys.argv = sys.argv[1:]
def reject_io(event, args):
    if event in ("open", "import", "os.mkdir"):
        raise RuntimeError("unexpected I/O before refusal")
sys.addaudithook(reject_io)
try:
    exec(code, {"__name__": "__main__", "__file__": source})
except SystemExit as error:
    if str(error) != "Integrity checks require assertions; rerun without Python optimization (-O/-OO).":
        raise RuntimeError("unexpected refusal") from None
else:
    raise RuntimeError("optimized extractor did not refuse")
print("refused-before-io")
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_receipt_path(args):
    """Protect private files through path, symlink and hard-link aliases."""
    output = args.receipt.resolve()
    exports = args.exports.resolve(strict=True)
    require(not output.is_relative_to(exports), ALIAS_REFUSAL)
    inputs = [args.binary, args.preflight]
    visited = set()
    for directory, children, files in os.walk(exports, followlinks=True):
        folder = Path(directory)
        metadata = folder.stat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in visited:
            children.clear()
            continue
        visited.add(identity)
        require(not output.is_relative_to(folder.resolve()), ALIAS_REFUSAL)
        inputs.extend(folder / name for name in files)
    for private in inputs:
        require(output != private.resolve(strict=True), ALIAS_REFUSAL)
        if args.receipt.exists():
            require(not args.receipt.samefile(private), ALIAS_REFUSAL)


def write_receipt(args, receipt):
    validate_receipt_path(args)
    # Replace the directory entry rather than opening an existing target for
    # truncation. A link introduced after validation cannot truncate its target.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=args.receipt.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps(receipt, indent=2) + "\n")
        validate_receipt_path(args)
        os.replace(temporary, args.receipt)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def arguments(path, binary, output):
    """Recover this bounded inventory's Path arguments without importing tools."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = []
    if path.name == "extract_import_thunks_18.py":
        names = ["--" + n for n in ("binary", "atlas", "exports", "preflight", "summary", "rows")]
    else:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
                require(isinstance(node.args[0], ast.Constant), "unrecognized argument declaration")
                names.append(node.args[0].value)
    result = []
    for name in names:
        if name in ("binary", "--binary"):
            value = binary
        elif name in ("--output", "--summary", "--rows"):
            value = output / (name[2:] + ".json")
        else:
            # Digest rejection must precede any dependency reads in normal mode.
            value = output / ("absent-" + name[2:])
        if name.startswith("--"):
            result.append(name)
        result.append(str(value))
    return result


def run(args):
    validate_receipt_path(args)
    require(digest(args.binary) == SHA, "check requires pinned specimen")
    env = dict(os.environ)
    env.pop("PYTHONOPTIMIZE", None)
    inventory = []
    for path in sorted((ROOT / "scripts").glob("extract_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        count = sum(isinstance(node, ast.Assert) for node in ast.walk(tree))
        if count and path.name != EXCLUDED:
            inventory.append((path, count))
    require(len(inventory) == 20, "extractor inventory changed; review the audit scope")
    results = []
    with tempfile.TemporaryDirectory(prefix="extractor-integrity-20-") as temporary:
        temp = Path(temporary)
        wrong = temp / "synthetic-wrong-specimen.bin"
        wrong.write_bytes(b"synthetic wrong specimen; contains no original bytes\n")
        for path, count in inventory:
            output = temp / path.stem
            output.mkdir()
            cli = arguments(path, wrong, output)
            normal = subprocess.run([sys.executable, str(path), *cli], cwd=temp,
                                    env=env, capture_output=True, text=True)
            require(normal.returncode != 0 and
                    ("AssertionError" in normal.stderr or "ValueError" in normal.stderr),
                    path.name + ": wrong specimen was not rejected by integrity validation")
            require(not list(output.iterdir()), path.name + ": wrong specimen wrote output")
            modes = []
            for mode in ("-O", "-OO", "PYTHONOPTIMIZE=1"):
                mode_env = dict(env)
                flags = [mode] if mode.startswith("-") else []
                if not flags:
                    mode_env["PYTHONOPTIMIZE"] = "1"
                valid_cli = arguments(path, args.binary, output)
                direct = subprocess.run([sys.executable, *flags, str(path), *valid_cli],
                                        cwd=temp, env=mode_env, capture_output=True, text=True)
                require(direct.returncode != 0 and direct.stderr.strip() == REFUSAL and not direct.stdout,
                        path.name + ": optimized CLI did not refuse")
                probe = subprocess.run([sys.executable, *flags, "-c", PROBE, str(path), *valid_cli],
                                       cwd=temp, env=mode_env, capture_output=True, text=True)
                require(probe.returncode == 0 and probe.stdout.strip() == "refused-before-io" and not probe.stderr,
                        path.name + ": optimized import/I/O probe failed")
                require(not list(output.iterdir()), path.name + ": optimized mode wrote output")
                modes.append(mode)
            results.append(dict(script="scripts/" + path.name, integrity_assertions=count,
                                wrong_specimen_normal="rejected; no output",
                                optimized_modes=modes, optimized_cli="refused; no output",
                                optimized_audit_probe="refused before any import/open/mkdir"))
        regenerated = temp / "match-dispatch-17-sites.json"
        positive = subprocess.run([sys.executable, str(ROOT / "scripts/extract_match_dispatch_17.py"),
                                   str(args.binary), "--exports", str(args.exports),
                                   "--preflight", str(args.preflight), "--output", str(regenerated)],
                                  cwd=temp, env=env, capture_output=True, text=True)
        require(positive.returncode == 0 and regenerated.is_file(), "R17 pinned-input regeneration failed")
        retained = ROOT / "evidence/match-dispatch-17-sites.json"
        require(regenerated.read_bytes() == retained.read_bytes(), "R17 retained evidence changed")
        positive_digest = digest(regenerated)
    require(digest(args.binary) == SHA, "private specimen changed during check")
    return dict(work_unit="R20-V2", specimen_sha256=SHA, specimen_read_only=True,
                python_version=sys.version.split()[0], decoder="Capstone 5.0.7 (checked by R17 extractor)",
                check="optimized-mode integrity refusal; retained findings unchanged",
                excluded_extractor="scripts/" + EXCLUDED,
                audited_assert_extractors=len(results),
                assertion_free_extractors=sorted("scripts/" + p.name for p in (ROOT / "scripts").glob("extract_*.py")
                                                if not any(isinstance(n, ast.Assert) for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))))),
                negative_checks=results,
                normal_r17_regeneration=dict(entries=["006fa250", "006fa490", "006f09f0"],
                                             retained_output_byte_identical=True, sha256=positive_digest),
                public_data="Hashes and status only; synthetic wrong input and all extractor outputs were temporary")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--exports", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    options = parser.parse_args()
    receipt = run(options)
    write_receipt(options, receipt)
    print("20 extractors: normal wrong-specimen rejection and three optimized refusal modes passed; R17 output unchanged")
