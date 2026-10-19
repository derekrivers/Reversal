#!/usr/bin/env python3
"""R30-B review regressions against clean archives of the staged Git tree.

Stage the intended task files first. Private inputs remain external/read-only.
Both Python modes start with no results/; receipt mutations touch archive copies.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def need(value,message):
    if not value:raise ValueError(message)


def run(args,cwd,expected_failure=None):
    result=subprocess.run([str(x) for x in args],cwd=cwd,capture_output=True,text=True)
    output=result.stdout+result.stderr
    if expected_failure is None:
        need(result.returncode==0,'command failed: '+output)
    else:
        need(result.returncode!=0,'receipt mutation was accepted')
        need(expected_failure in output,'unexpected mutation failure: '+output)
    return result.stdout.strip()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    for name in ('exports09','exports10','runtime','node','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    for name in ('binary','exports09','exports10','runtime','node'):setattr(a,name,getattr(a,name).resolve())
    node_version=run([a.node,'--version'],root);need(node_version.startswith('v24.'),'Node 24 is required')
    tree=run(['git','write-tree'],root)
    archive=subprocess.run(['git','archive','--format=tar',tree],cwd=root,capture_output=True,check=True).stdout
    (root/'results').mkdir(parents=True,exist_ok=True)
    receipts=[];checks={}
    with tempfile.TemporaryDirectory(prefix='action33-effect-review-',dir=root/'results') as temporary:
        for label,flags in (('normal',[]),('optimized',['-O'])):
            checkout=Path(temporary)/label;checkout.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive)) as source:source.extractall(checkout,filter='data')
            need(not (checkout/'results').exists(),'archive unexpectedly contains results/')
            output=checkout/'results/receipt.json'
            command=[sys.executable,*flags,'scripts/verify_action33_effect_30.py',a.binary,
                     '--exports09',a.exports09,'--exports10',a.exports10,'--runtime',a.runtime,'--output',output]
            checks['clean_archive_'+label]=run(command,checkout)
            receipt=output.read_bytes();retained=(checkout/'evidence/action33-effect-30-integrity.json').read_bytes()
            need(receipt==retained,label+' receipt differs from retained bytes');receipts.append(receipt)
            checks['node_'+label]=run([a.node,'scripts/check-action33-effect-30.mjs'],checkout)
            if label=='normal':
                path=checkout/'evidence/action33-effect-30-integrity.json'
                for name,mutate in (('status',lambda r:r.update(status='failed')),
                                    ('negative_checks',lambda r:r.update(negative_checks={}))):
                    changed=json.loads(retained);mutate(changed)
                    path.write_text(json.dumps(changed,indent=2)+'\n',encoding='utf-8',newline='\n')
                    try:run([a.node,'scripts/check-action33-effect-30.mjs'],checkout,'integrity receipt SHA-256')
                    finally:path.write_bytes(retained)
                    checks['mutated_'+name]='rejected: integrity receipt SHA-256'
                checks['full_runner']=run([a.node,'scripts/check-research.mjs'],checkout)
        need(receipts[0]==receipts[1],'normal and optimized receipts differ')
    result={'unit':'R30-B','status':'passed','staged_tree':tree,'node':node_version,
            'receipt_sha256':hashlib.sha256(receipts[0]).hexdigest(),'checks':checks}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in result.items() if k!='checks'}));print('checks:',', '.join(checks))


if __name__=='__main__':main()
