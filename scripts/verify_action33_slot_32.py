#!/usr/bin/env python3
"""R32-B private-input reproduction, integrity mutations and privacy gates."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_slot_32 as slot
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
    p=slot.parser();p.add_argument('receipt',type=Path);a=p.parse_args()
    pe,decoded,native,sites=slot.extract(a)
    retained=a.output.read_bytes();value=life.privacy_check(retained,pe)
    inputs=[str(getattr(a,name)) for name in ('binary','state','staff','focused','support','exports25','slot')]
    with tempfile.TemporaryDirectory(prefix='r32b-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(slot.__file__)),*inputs,str(output)],
                           check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O retained evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x6eadb2,3)+2]^=1
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.slot=ChangedManifest(a.slot)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:slot.extract(specimen)),
            reject('changed slot manifest','slot manifest mismatch',lambda:slot.extract(manifest))]
    # Re-enter extraction so runtime admitted ranges are restored after failed guards.
    slot.extract(a)
    original=life.rows((a.slot/'006eada0.asm').read_bytes());bad=dict(original)
    bad[0x6eadb2]='MOV word ptr [EAX + 0x27],CX'
    probes.append(reject('resealed initializer width operand','PE/native operand mismatch',
                         lambda:life.compare([decoded[0x6eadb2]],bad)))
    probes.append(reject('executed wrong initializer side field','complete nonstack memory mismatch slots',
                         lambda:slot.produce(bytes(changed),decoded)))
    wrong_read=bytearray(pe);wrong_read[life.offset(pe,0x6eaf77,3)+2]^=1
    probes.append(reject('executed wrong prior-side read','placement side read width/source mismatch',
                         lambda:slot.produce(bytes(wrong_read),decoded)))
    wrong_store=bytearray(pe);wrong_store[life.offset(pe,0x6eaec5,6)+2]^=4
    probes.append(reject('executed wrong slot context store','complete nonstack memory mismatch slots',
                         lambda:slot.produce(bytes(wrong_store),decoded)))
    fragment=pe[life.offset(pe,0x6eada0,32):life.offset(pe,0x6eada0,32)+32]
    probes.append(reject('raw private fragment in container','private fragment in compressed evidence',
                         lambda:life.privacy_check(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment in expanded JSON','private fragment in expanded evidence',
                         lambda:life.privacy_check(life.pack(hidden),pe)))
    probes.append(reject('oversized gzip expansion','expanded evidence size limit',
                         lambda:life.privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    samples=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)]
             for start,size in life.RANGES.items()]
    pos=life.offset(pe,0x9e7f28,1);samples.append(pe[pos:pe.index(b'\0',pos)])
    forms=[v for sample in samples for v in (sample,sample.hex().encode(),base64.b64encode(sample))]
    for name in ('reports/action33-slot-32.md','scripts/extract_action33_slot_32.py',
                 'scripts/verify_action33_slot_32.py','scripts/check-action33-slot-32.mjs'):
        life.need(not any(sample in Path(name).read_bytes() for sample in forms),'private code/source in task file '+name)
    result={'unit':'R32-B','status':'passed','specimen_sha256':life.SPECIMEN,
      'evidence_sha256':life.sha(retained),'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'compressed_bytes':len(retained),'expanded_canonical_bytes':len(life.compact(value))+1,
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'compared_instructions':sum(r['instructions'] for r in sites['ranges']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded bytes plus authored files scanned for raw/hex/base64 code/source samples',
      'limits':'separate synthetic original entries; no enclosing caller, loaded game, complete slot, lookup object or normal effect return'}
    a.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R32-B','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':
    main()
