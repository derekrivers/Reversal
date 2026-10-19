#!/usr/bin/env python3
"""Exercise R28-B provenance/operand gates and Python optimization parity."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import extract_merge_dependencies_28 as module


def need(condition, message):
    if not condition:
        raise ValueError(message)


def rejected(action, label):
    try:
        action()
    except (ValueError, KeyError):
        return
    raise ValueError("mutation admitted: " + label)


def write_json(path, item):
    path.write_text(json.dumps(item, indent=2)+"\n", encoding="utf-8", newline="\n")


def run(exe, exports, preflight, static, oracle):
    py=Path(sys.executable)
    extractor=Path(__file__).with_name("extract_merge_dependencies_28.py")
    emulator=Path(__file__).with_name("emulate_merge_initializer_28.py")
    outcomes=[]
    with tempfile.TemporaryDirectory() as folder:
        temp=Path(folder)
        normal=temp/"normal.json"
        optimized=temp/"optimized.json"
        normal_oracle=temp/"normal.json.gz"
        optimized_oracle=temp/"optimized.json.gz"
        for flag,destination,fixture in (([],normal,normal_oracle),(["-O"],optimized,optimized_oracle)):
            subprocess.run([str(py),*flag,str(extractor),str(exe),str(exports),str(preflight),str(destination)],check=True)
            subprocess.run([str(py),*flag,str(emulator),str(exe),str(exports),str(preflight),str(fixture)],check=True)
        need(normal.read_bytes()==optimized.read_bytes()==static.read_bytes(),"static normal/-O mismatch")
        need(normal_oracle.read_bytes()==optimized_oracle.read_bytes()==oracle.read_bytes(),"oracle normal/-O mismatch")
        outcomes.append("normal/-O static and original-entry oracle identical")

        changed_exe=temp/"changed.exe"
        data=bytearray(exe.read_bytes());data[0x28d024]^=1
        changed_exe.write_bytes(data)
        rejected(lambda:module.extract(changed_exe,exports,preflight),"changed PE")
        outcomes.append("changed PE rejected")

        changed=temp/"exports"
        shutil.copytree(exports,changed)
        asm=changed/"0068d020.asm"
        asm.write_text(asm.read_text().replace("[EAX + 0x2]","[EAX + 0x3]"),encoding="utf-8",newline="\n")
        manifest=json.loads((changed/"manifest.json").read_text())
        raw=asm.read_bytes()
        manifest["files"]["0068d020.asm"]={"bytes":len(raw),"sha256":module.sha(raw)}
        write_json(changed/"manifest.json",manifest)
        old_manifest=module.MANIFEST
        module.MANIFEST=module.sha((changed/"manifest.json").read_bytes())
        try:
            rejected(lambda:module.extract(exe,changed,preflight),"independently resealed native operand")
        finally:
            module.MANIFEST=old_manifest
        outcomes.append("resealed native operand rejected by complete instruction comparator")

        changed_preflight=temp/"preflight.json"
        prior=json.loads(preflight.read_text())
        prior["sites"][2]["function_name"]="FUN_0068d020_false"
        write_json(changed_preflight,prior)
        old_preflight=module.PREFLIGHT
        old_manifest=module.MANIFEST
        module.PREFLIGHT=module.sha(changed_preflight.read_bytes())
        changed_manifest=json.loads((changed/"manifest.json").read_text())
        changed_manifest["preflight_sha256"]=module.PREFLIGHT
        # Restore native assembly, then reseal the dependent manifest.
        shutil.copyfile(exports/"0068d020.asm",changed/"0068d020.asm")
        changed_manifest["files"]["0068d020.asm"]=json.loads((exports/"manifest.json").read_text())["files"]["0068d020.asm"]
        write_json(changed/"manifest.json",changed_manifest)
        module.MANIFEST=module.sha((changed/"manifest.json").read_bytes())
        try:
            rejected(lambda:module.extract(exe,changed,changed_preflight),"resealed old function identity")
        finally:
            module.MANIFEST=old_manifest
            module.PREFLIGHT=old_preflight
        outcomes.append("resealed exact-old native identity rejected")
    return {"work_unit":"R28-B","specimen_sha256":module.PINNED,
            "static_sha256":module.sha(static.read_bytes()),"oracle_sha256":module.sha(oracle.read_bytes()),
            "negative_checks":outcomes}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","exports","preflight","static","oracle","output"):
        parser.add_argument(name,type=Path)
    args=parser.parse_args()
    write_json(args.output,run(args.exe,args.exports,args.preflight,args.static,args.oracle))
