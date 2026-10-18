#!/usr/bin/env python3
"""Reproduce R26-A normal/-O evidence and reject input, operand and result mutations."""
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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, expected_success):
    result = subprocess.run(command, capture_output=True, text=True)
    need((result.returncode == 0) == expected_success,
         "unexpected exit code "+str(result.returncode)+" "+result.stderr[-600:])
    return result


def check(args):
    scripts = Path(__file__).resolve().parent
    extractor, emulator = scripts/"extract_match_dependencies_26.py", scripts/"emulate_match_dependencies_26.py"
    with tempfile.TemporaryDirectory(prefix="match-dependencies-26-",dir=args.scratch) as temp_name:
        temp = Path(temp_name)
        products = {}
        for title,script in (("sites",extractor),("oracle",emulator)):
            for mode,flag in (("normal",[]),("optimized",["-O"])):
                output = temp/f"{title}-{mode}.json"
                run([sys.executable,*flag,str(script),str(args.binary),"--exports",str(args.exports),
                     "--preflight",str(args.preflight),"--output",str(output)],True)
                products[(title,mode)] = output
            need(products[(title,"normal")].read_bytes() == products[(title,"optimized")].read_bytes(),
                 title+" normal/-O mismatch")
        need(products[("sites","normal")].read_bytes() == args.sites.read_bytes(),"retained static sites differ")
        need(products[("oracle","normal")].read_bytes() == args.oracle.read_bytes(),"retained oracle differs")
        sites = json.loads(args.sites.read_text(encoding="utf-8"))
        oracle = json.loads(args.oracle.read_text(encoding="utf-8"))
        need([sites["bodies"][key]["instruction_count"] for key in ("0062e700","0062be00")]
             == [97,117],"static instruction coverage changed")
        need(oracle["function_cases"] == 77 and oracle["executed_instruction_steps"] == 2185,
             "original case coverage changed")
        changed = temp/"altered.exe"
        shutil.copyfile(args.binary,changed)
        with changed.open("r+b") as stream:
            stream.seek(int(sites["bodies"]["0062e700"]["file_offset"],16))
            old = stream.read(1)
            stream.seek(int(sites["bodies"]["0062e700"]["file_offset"],16))
            stream.write(bytes([old[0]^1]))
        bad_exports = temp/"exports"
        shutil.copytree(args.exports,bad_exports)
        asm = bad_exports/"0062e700.asm"
        raw = asm.read_bytes()
        mutated = raw.replace(b"CMP byte ptr [ESI],0x51",b"CMP byte ptr [ESI],0x50",1)
        need(mutated != raw,"operand mutation did not alter export")
        asm.write_bytes(mutated)
        negatives = {}
        for label,binary,exports in (("altered_specimen",changed,args.exports),
                                     ("altered_native_operand",args.binary,bad_exports)):
            for mode,flag in (("normal",[]),("optimized",["-O"])):
                output = temp/f"{label}-{mode}.json"
                failure = run([sys.executable,*flag,str(extractor),str(binary),"--exports",str(exports),
                               "--preflight",str(args.preflight),"--output",str(output)],False)
                need(not output.exists() and "ValueError:" in failure.stderr,"negative wrote output or lacked explicit error")
                negatives[label+"_"+mode] = {"rejected_before_output":True,"error_class":"ValueError"}
        resealed = temp/"resealed-exports"
        shutil.copytree(bad_exports,resealed)
        manifest_file = resealed/"manifest.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        manifest["files"]["0062e700.asm"] = {"bytes":len(mutated),
                                                "sha256":hashlib.sha256(mutated).hexdigest()}
        manifest_file.write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
        diagnostic = ("import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
                      "import extract_match_dependencies_26 as x;x.MANIFEST=sys.argv[2];"
                      "x.extract(Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]))")
        for mode,flag in (("normal",[]),("optimized",["-O"])):
            failure = run([sys.executable,*flag,"-c",diagnostic,str(scripts),sha(manifest_file),
                           str(args.binary),str(resealed),str(args.preflight)],False)
            need("native/original operand mismatch at 0062e7ac" in failure.stderr,
                 "resealed native mutation did not reach operand comparator")
            negatives["resealed_native_operand_"+mode] = {"rejected":True,"reason":"operand mismatch"}
        for mode,flag in (("normal",[]),("optimized",["-O"])):
            output = temp/f"bad-emulator-{mode}.json"
            failure = run([sys.executable,*flag,str(emulator),str(changed),"--exports",str(args.exports),
                           "--preflight",str(args.preflight),"--output",str(output)],False)
            need(not output.exists() and "specimen size/SHA-256 mismatch" in failure.stderr,
                 "emulator wrong specimen gate missed")
            negatives["emulator_altered_specimen_"+mode] = {"rejected_before_output":True}
        width_exports = temp/"width-exports"
        shutil.copytree(args.exports,width_exports)
        width_asm = width_exports/"0062e700.asm"
        width_raw = width_asm.read_bytes().replace(b"MOV EAX,dword ptr [EBX]",b"MOV EAX,word ptr [EBX]",1)
        need(width_raw != width_asm.read_bytes(),"width mutation did not apply")
        width_asm.write_bytes(width_raw)
        width_manifest_path = width_exports/"manifest.json"
        width_manifest = json.loads(width_manifest_path.read_text(encoding="utf-8"))
        width_manifest["files"]["0062e700.asm"] = {"bytes":len(width_raw),"sha256":hashlib.sha256(width_raw).hexdigest()}
        width_manifest_path.write_text(json.dumps(width_manifest,indent=2)+"\n",encoding="utf-8",newline="\n")
        for mode,flag in (("normal",[]),("optimized",["-O"])):
            failure=run([sys.executable,*flag,"-c",diagnostic,str(scripts),sha(width_manifest_path),
                         str(args.binary),str(width_exports),str(args.preflight)],False)
            need("native/original operand mismatch at 0062e77c" in failure.stderr,"native width mutation missed")
            negatives["resealed_native_width_"+mode] = {"rejected":True,"reason":"operand width mismatch"}
        good = run([str(args.node),str(args.checker),str(args.oracle)],True)
        need('"checked_cases":77' in good.stdout,"Node checker case count changed")
        for mutation, reason in (("--mutate-result","register/path mismatch"),
                                 ("--mutate-effect","ordered memory effect mismatch")):
            bad = run([str(args.node),str(args.checker),str(args.oracle),mutation],False)
            need(reason in bad.stderr,"TypeScript mutation missed")
            negatives[mutation[2:]] = {"rejected":True,"reason":reason}
        tampered = temp/"tampered-oracle.json"
        tampered.write_bytes(args.oracle.read_bytes()[:-2])
        bad = run([str(args.node),str(args.checker),str(tampered)],False)
        need("oracle SHA-256 mismatch" in bad.stderr,"oracle mutation missed")
        negatives["tampered_oracle"] = {"rejected":True,"reason":"oracle SHA mismatch"}
        return {"work_unit":"R26-A","normal_optimized_sites_identical":True,
                "normal_optimized_oracle_identical":True,"sites_sha256":sha(args.sites),
                "oracle_sha256":sha(args.oracle),"negative_checks":negatives,
                "scope":"synthetic call-free original entry-to-return cases; all callee paths and the complete merge body remain static"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary",type=Path)
    p.add_argument("--exports",type=Path,required=True)
    p.add_argument("--preflight",type=Path,required=True)
    p.add_argument("--sites",type=Path,required=True)
    p.add_argument("--oracle",type=Path,required=True)
    p.add_argument("--checker",type=Path,required=True)
    p.add_argument("--node",type=Path,required=True)
    p.add_argument("--scratch",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args = p.parse_args()
    args.scratch.mkdir(parents=True,exist_ok=True)
    result = check(args)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
