#!/usr/bin/env python3
"""Verify the retained TypeScript checker rejects altered observations and fixtures."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def run(node, checker, oracle):
    baseline=subprocess.run([str(node),str(checker),str(oracle)],capture_output=True,text=True)
    if baseline.returncode:
        raise ValueError("baseline TypeScript checker failed: "+baseline.stderr)
    labels=[]
    for mode in ("--mutate-result","--mutate-effect","--mutate-memory","--mutate-abi"):
        check=subprocess.run([str(node),str(checker),str(oracle),mode],capture_output=True,text=True)
        if check.returncode==0:
            raise ValueError("TypeScript mutation admitted: "+mode)
        labels.append(mode+" rejected")
    with tempfile.TemporaryDirectory() as folder:
        altered=Path(folder)/"altered.json.gz"
        raw=bytearray(oracle.read_bytes());raw[-1]^=1;altered.write_bytes(raw)
        check=subprocess.run([str(node),str(checker),str(altered)],capture_output=True,text=True)
        if check.returncode==0 or "oracle SHA-256 mismatch" not in check.stderr:
            raise ValueError("altered oracle was not rejected at digest gate")
    labels.append("altered oracle rejected before decode")
    return {"work_unit":"R28-B","node_version":subprocess.run([str(node),"--version"],capture_output=True,text=True,check=True).stdout.strip(),
            "baseline":json.loads(baseline.stdout),"negative_checks":labels}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("node","checker","oracle","output"):
        parser.add_argument(name,type=Path)
    args=parser.parse_args()
    args.output.write_text(json.dumps(run(args.node,args.checker,args.oracle),indent=2)+"\n",encoding="utf-8",newline="\n")
