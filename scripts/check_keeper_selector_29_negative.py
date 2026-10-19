#!/usr/bin/env python3
"""R29-A normal/-O parity and corrupt-input rejection, including resealed native edits."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import extract_keeper_selector_29 as module
from emulate_keeper_selector_29 import normalize_gzip_header

def rejected(action,label):
    try:action()
    except ValueError:return label+' rejected'
    raise ValueError('mutation admitted: '+label)

def run(exe,exports,preflight,sites,oracle):
    result=[]
    with tempfile.TemporaryDirectory() as folder:
        temp=Path(folder)
        extractor=Path(__file__).with_name('extract_keeper_selector_29.py')
        emulator=Path(__file__).with_name('emulate_keeper_selector_29.py')
        for flag in ([],['-O']):
            out=temp/('static'+str(len(flag))+'.json')
            fixture=temp/('oracle'+str(len(flag))+'.json.gz')
            common=[str(exe),'--exports',str(exports),'--preflight',str(preflight)]
            subprocess.run([sys.executable,*flag,str(extractor),*common,'--output',str(out)],check=True,capture_output=True)
            subprocess.run([sys.executable,*flag,str(emulator),*common,'--output',str(fixture)],check=True,capture_output=True)
            if out.read_bytes()!=sites.read_bytes() or fixture.read_bytes()!=oracle.read_bytes():
                raise ValueError('normal/-O retained evidence mismatch')
        result.append('normal/-O static and oracle bytes identical')
        canonical=oracle.read_bytes()
        for osbyte in (0x03,0x0a):
            variant=canonical[:9]+bytes([osbyte])+canonical[10:]
            if normalize_gzip_header(variant)!=canonical:
                raise ValueError(f'gzip OS-byte {osbyte:02x} normalization mismatch')
        result.append('gzip OS bytes 03/0a normalize to retained FF oracle')
        changed=temp/'changed.exe';raw=bytearray(exe.read_bytes());raw[0x2ce110]^=1;changed.write_bytes(raw)
        result.append(rejected(lambda:module.extract(changed,exports,preflight),'changed PE'))
        changed_exports=temp/'exports';shutil.copytree(exports,changed_exports)
        asm=changed_exports/'006ce110.asm'
        asm.write_text(asm.read_text().replace('[ECX + 0xf59e]','[ECX + 0xf59f]',1),encoding='utf-8',newline='\n')
        mutant=json.loads((changed_exports/'manifest.json').read_text())
        data=asm.read_bytes();mutant['files']['006ce110.asm']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        (changed_exports/'manifest.json').write_text(json.dumps(mutant,indent=2)+'\n',encoding='utf-8',newline='\n')
        old=module.MANIFEST;module.MANIFEST=module.sha((changed_exports/'manifest.json').read_bytes())
        try:result.append(rejected(lambda:module.extract(exe,changed_exports,preflight),'resealed native operand'))
        finally:module.MANIFEST=old
        badpre=temp/'preflight.json';pre=json.loads(preflight.read_text())
        for row in pre['sites']:
            if row['address']=='006ce110':row['function_name']='wrong_name'
        badpre.write_text(json.dumps(pre,indent=2)+'\n',encoding='utf-8',newline='\n')
        oldpre=module.PREFLIGHT;oldman=module.MANIFEST
        module.PREFLIGHT=module.sha(badpre.read_bytes())
        mutant=json.loads((exports/'manifest.json').read_text());mutant['preflight_sha256']=module.PREFLIGHT
        shutil.copyfile(exports/'006ce110.asm',asm)
        mutant['files']['006ce110.asm']=json.loads((exports/'manifest.json').read_text())['files']['006ce110.asm']
        (changed_exports/'manifest.json').write_text(json.dumps(mutant,indent=2)+'\n',encoding='utf-8',newline='\n')
        module.MANIFEST=module.sha((changed_exports/'manifest.json').read_bytes())
        try:result.append(rejected(lambda:module.extract(exe,changed_exports,badpre),'resealed exact-old annotation'))
        finally:module.PREFLIGHT=oldpre;module.MANIFEST=oldman
    return {'unit':'R29-A','specimen_sha256':module.SPECIMEN,
            'sites_sha256':module.sha(sites.read_bytes()),'oracle_sha256':module.sha(oracle.read_bytes()),
            'checks':result}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('exe','exports','preflight','sites','oracle','output'):p.add_argument(name,type=Path)
    a=p.parse_args();a.output.write_text(json.dumps(run(a.exe,a.exports,a.preflight,a.sites,a.oracle),indent=2)+'\n',encoding='utf-8',newline='\n')
