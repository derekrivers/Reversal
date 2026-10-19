#!/usr/bin/env python3
"""Negative integrity checks for the R28-A extractor under normal and -O Python."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

BASE=Path(__file__).resolve().parents[1]
ROOT=BASE.parent
EXE=ROOT/'Reversal/downloads/cm0102.exe'
EXPORTS=ROOT/'private-native-verify/exports-28'
PREFLIGHT=ROOT/'private-native-verify/preflight-28.json'
SCRIPT=BASE/'scripts/extract_sort_helpers_28.py'

def run(optimized,exe,exports,preflight,out):
    args=[sys.executable]+(['-O'] if optimized else [])+[str(SCRIPT),str(exe),'--exports',str(exports),
          '--preflight',str(preflight),'--output',str(out)]
    return subprocess.run(args,capture_output=True,text=True)

def need(ok,msg):
    if not ok:raise ValueError(msg)

def main():
    with tempfile.TemporaryDirectory() as folder:
        d=Path(folder);out=d/'sites.json'
        for optimized in (False,True):
            p=run(optimized,EXE,EXPORTS,PREFLIGHT,out)
            need(p.returncode==0,p.stderr)
            need(out.read_bytes()==(BASE/'evidence/sort-helpers-28-sites.json').read_bytes(),'positive output mismatch')
        mutant=d/'mutant.exe';mutant.write_bytes(EXE.read_bytes());raw=bytearray(mutant.read_bytes());raw[0x5454d5]^=1;mutant.write_bytes(raw)
        export_copy=d/'exports';shutil.copytree(EXPORTS,export_copy)
        native=export_copy/'009454d5.asm';native.write_bytes(native.read_bytes()+b'X')
        badpre=d/'preflight.json';badpre.write_bytes(PREFLIGHT.read_bytes()+b'X')
        for label,exe,exports,pre in [('specimen',mutant,EXPORTS,PREFLIGHT),('native-export',EXE,export_copy,PREFLIGHT),
                                      ('preflight',EXE,EXPORTS,badpre)]:
            for optimized in (False,True):
                p=run(optimized,exe,exports,pre,out)
                need(p.returncode!=0 and ('ValueError' in p.stderr),f'{label} admitted under optimized={optimized}')
        print('R28-A: normal/-O positive results match; 3 corrupt-input classes rejected under both modes.')

if __name__=='__main__':main()
