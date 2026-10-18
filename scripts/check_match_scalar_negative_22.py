#!/usr/bin/env python3
"""Exercise specimen, manifest and operand rejection in normal and optimized Python."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import extract_match_scalar_22 as m


def expect_rejection(label, invoke, words):
    try:
        invoke()
    except ValueError as error:
        m.need(any(word in str(error) for word in words), label+': wrong rejection: '+str(error))
        return {'case':label, 'rejected':True, 'reason':str(error)}
    raise ValueError(label+': unexpectedly accepted')


def internal(binary, exports, preflight):
    result=[]
    with tempfile.TemporaryDirectory(prefix='r22a-negative-') as tmp:
        dest=Path(tmp)
        bad_binary=dest/'bad.exe'
        bytes_=bytearray(binary.read_bytes()); bytes_[-1]^=1
        bad_binary.write_bytes(bytes_)
        result.append(expect_rejection('one-byte specimen mutation',lambda:m.extract(bad_binary,exports,preflight),['specimen SHA-256']))
        bad_exports=dest/'exports'; shutil.copytree(exports,bad_exports)
        manifest=bad_exports/'manifest.json'
        manifest.write_bytes(manifest.read_bytes()+b' ')
        result.append(expect_rejection('manifest mutation',lambda:m.extract(binary,bad_exports,preflight),['manifest SHA-256']))
        # Reseal the local fixture metadata so the full operand comparison is reached.
        manifest.write_bytes((exports/'manifest.json').read_bytes())
        asm=bad_exports/'0062c3d0.asm'
        content=asm.read_text(encoding='utf-8')
        m.need('MOV EDX,EAX' in content,'expected mutation site missing')
        asm.write_text(content.replace('MOV EDX,EAX','MOV EDX,ECX',1),encoding='utf-8',newline='\n')
        metadata=json.loads(manifest.read_text(encoding='utf-8'))
        metadata['files']['0062c3d0.asm']['bytes']=len(asm.read_bytes())
        metadata['files']['0062c3d0.asm']['sha256']=m.sha(asm.read_bytes())
        manifest.write_text(json.dumps(metadata,separators=(',',':')),encoding='utf-8',newline='\n')
        original=m.MANIFEST
        try:
            m.MANIFEST=m.sha(manifest.read_bytes())
            result.append(expect_rejection('resealed operand mutation',lambda:m.extract(binary,bad_exports,preflight),['native operand mismatch']))
        finally:
            m.MANIFEST=original
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path); p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True); p.add_argument('--node',type=Path)
    p.add_argument('--oracle',type=Path); p.add_argument('--output',type=Path)
    p.add_argument('--internal',action='store_true')
    a=p.parse_args()
    if a.internal:
        print(json.dumps(internal(a.binary,a.exports,a.preflight)))
    else:
        out=[]
        for optimized in (False,True):
            command=[sys.executable]+(['-O'] if optimized else [])+[str(Path(__file__).resolve()),str(a.binary),'--exports',str(a.exports),'--preflight',str(a.preflight),'--internal']
            done=subprocess.run(command,capture_output=True,text=True,check=True)
            out.append({'mode':'optimized' if optimized else 'normal','checks':json.loads(done.stdout)})
        if a.node and a.oracle:
            command=[str(a.node),'reconstruction/check-match-scalar.ts',str(a.oracle),'--mutate-word']
            done=subprocess.run(command,capture_output=True,text=True)
            m.need(done.returncode != 0 and 'register mismatch' in done.stderr,'TypeScript word mutation not rejected')
            out.append({'mode':'Node24','checks':[{'case':'changed WORD read','rejected':True,'reason':'register mismatch'}]})
        if a.output:
            a.output.write_text(json.dumps({'work_unit':'R22-A','negative_checks':out},indent=2)+'\n',encoding='utf-8',newline='\n')
        print(json.dumps({'normal_and_optimized_rejections':6,'typescript_mutation_rejected':bool(a.node and a.oracle)}))
