#!/usr/bin/env python3
"""R33-B private-input reproduction, independent mutations and bounded privacy."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_owner_33 as owner
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,ChangedManifest,reject

FILES=('reports/action33-owner-33.md','scripts/extract_action33_owner_33.py',
       'scripts/verify_action33_owner_33.py','scripts/check-action33-owner-33.mjs')


def main():
    p=owner.parser();p.add_argument('receipt',type=Path);a=p.parse_args()
    pe,decoded,sites=owner.extract(a);retained=a.output.read_bytes();value=life.privacy_check(retained,pe)
    inputs=[str(getattr(a,name)) for name in ('binary','state','staff','focused','support','exports25','slot','owner','database')]
    with tempfile.TemporaryDirectory(prefix='r33b-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(owner.__file__)),*inputs,str(output)],check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O retained evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x6b7f4e,6)+2]^=4
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.owner=ChangedManifest(a.owner)
    dbmanifest=copy.copy(a);dbmanifest.database=ChangedManifest(a.database)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:owner.extract(specimen)),
        reject('changed owner manifest','owner manifest mismatch',lambda:owner.extract(manifest)),
        reject('changed database manifest','owner manifest mismatch',lambda:owner.extract(dbmanifest))]
    owner.extract(a)
    native=life.rows((a.owner/'006b7f20.asm').read_bytes());wrong=dict(native)
    wrong[0x6b7f4e]='MOV word ptr [EBX + 0x4792],DX'
    probes.append(reject('resealed owner-store width','PE/native operand mismatch',lambda:life.compare([decoded[0x6b7f4e]],wrong)))
    probes.append(reject('executed wrong owner-store field','complete nonstack memory mismatch match',lambda:owner.produce(bytes(changed),decoded)))
    pointer=bytearray(pe);pointer[life.offset(pe,0x84c294,4)+3]^=4
    probes.append(reject('executed wrong club-pointer destination','producer complete stack mismatch',lambda:owner.produce(bytes(pointer),decoded)))
    consumer=bytearray(pe);consumer[life.offset(pe,0x6eaf95,3)+2]=0x20
    probes.append(reject('executed away-club read on home branch','placement owner alias read mismatch',lambda:owner.produce(bytes(consumer),decoded)))
    fragment=pe[life.offset(pe,0x6b7f20,32):life.offset(pe,0x6b7f20,32)+32]
    probes.append(reject('raw private fragment in container','private fragment in compressed evidence',lambda:life.privacy_check(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment in expanded JSON','private fragment in expanded evidence',lambda:life.privacy_check(life.pack(hidden),pe)))
    probes.append(reject('oversized gzip expansion','expanded evidence size limit',lambda:life.privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    samples=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)] for start,size in life.RANGES.items()]
    pos=life.offset(pe,0x9e7f28,1);samples.append(pe[pos:pe.index(b'\0',pos)])
    forms=[v for sample in samples for v in (sample,sample.hex().encode(),base64.b64encode(sample))]
    for name in FILES:life.need(not any(sample in Path(name).read_bytes() for sample in forms),'private code/source in task file '+name)
    result={'unit':'R33-B','status':'passed','specimen_sha256':life.SPECIMEN,
      'evidence_sha256':life.sha(retained),'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'compressed_bytes':len(retained),'expanded_canonical_bytes':len(life.compact(value))+1,
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'compared_instructions':sum(r['instructions'] for r in sites['ranges']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded bytes plus authored files scanned for raw/hex/base64 code/source samples',
      'limits':owner.SCOPE}
    a.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R33-B','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':main()
