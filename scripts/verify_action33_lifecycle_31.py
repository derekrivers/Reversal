#!/usr/bin/env python3
"""Reproduce R31-B evidence, optimized integrity and compressed/expanded privacy."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import extract_action33_lifecycle_31 as life


class MemoryFile:
    def __init__(self,raw): self.raw=raw
    def read_bytes(self): return self.raw


class ChangedManifest:
    def __init__(self,folder): self.folder=folder
    def __truediv__(self,name):
        return MemoryFile((self.folder/name).read_bytes()+b' ') if name=='manifest.json' else self.folder/name


def reject(label,gate,work):
    try:
        work()
    except ValueError as exc:
        life.need(gate in str(exc),'wrong negative gate '+label+': '+str(exc))
        return label+' rejected'
    raise ValueError('mutation admitted '+label)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','state','staff','focused','support','exports25','evidence','output'):
        p.add_argument(name,type=Path)
    a=p.parse_args();pe,decoded,native,sites=life.extract(a)
    retained=a.evidence.read_bytes();value=life.privacy_check(retained,pe)
    inputs=[str(getattr(a,name)) for name in ('binary','state','staff','focused','support','exports25')]
    with tempfile.TemporaryDirectory(prefix='r31b-public-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(life.__file__)),*inputs,str(output)],
                           check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O retained evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x896a14,3)+2]^=1
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.state=ChangedManifest(a.state)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:life.extract(specimen)),
            reject('changed native manifest','manifest mismatch',lambda:life.extract(manifest))]
    bad=copy.copy(native[0x8968f0]);bad[0x896985]='MOV EAX,dword ptr [EDX + EDI + 0x6]'
    probes.append(reject('resealed roster-ID operand','PE/native operand mismatch',
                         lambda:life.compare([decoded[0x896985]],bad)))
    probes.append(reject('executed wrong returned staff base','lookup result/RET ABI mismatch',
                         lambda:life.produce(bytes(changed),decoded)))
    wrong_store=bytearray(pe);wrong_store[life.offset(pe,0x6eaec5,6)+2]^=4
    probes.append(reject('executed wrong slot context store','complete nonstack memory mismatch slots',
                         lambda:life.produce(bytes(wrong_store),decoded)))
    fragment=pe[life.offset(pe,0x8968f0,32):life.offset(pe,0x8968f0,32)+32]
    probes.append(reject('raw private fragment in compressed container','private fragment in compressed evidence',
                         lambda:life.privacy_check(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment in expanded JSON','private fragment in expanded evidence',
                         lambda:life.privacy_check(life.pack(hidden),pe)))
    probes.append(reject('oversized gzip expansion','expanded evidence size limit',
                         lambda:life.privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    # Check authored task files as well as compressed and expanded generated evidence.
    pos=life.offset(pe,0x9e7f28,1);source=pe[pos:pe.index(b'\0',pos)]
    import base64
    forms=(source,source.hex().encode(),base64.b64encode(source))
    for name in ('reports/action33-lifecycle-31.md','scripts/extract_action33_lifecycle_31.py',
                 'scripts/verify_action33_lifecycle_31.py','scripts/check-action33-lifecycle-31.mjs'):
        life.need(not any(sample in Path(name).read_bytes() for sample in forms),'private diagnostic source in task file')
    result={'unit':'R31-B','status':'passed','specimen_sha256':life.SPECIMEN,
      'evidence_sha256':life.sha(retained),'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'compressed_bytes':len(retained),'expanded_canonical_bytes':len(life.compact(value))+1,
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'compared_instructions':sum(r['instructions'] for r in sites['ranges']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded bytes scanned for original code/source in raw, hex and base64; no original pages retained',
      'limits':'synthetic function-entry fixture kernels; no game caller, loaded database, lookup-object initialization or normal effect return'}
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R31-B','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':
    main()
