#!/usr/bin/env python3
"""R35-C private regeneration, integrity and privacy probes, active under -O."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_fixture_35 as fixture
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,ChangedManifest,reject

FILES=('reports/action33-fixture-35.md','scripts/extract_action33_fixture_35.py',
       'scripts/verify_action33_fixture_35.py','scripts/check-action33-fixture-35.mjs')


def main():
    parser=fixture.parser();parser.add_argument('receipt',type=Path);a=parser.parse_args()
    pe,decoded,sites=fixture.extract(a)
    life.RANGES={start:end-start for start,(end,_,_) in fixture.RANGES.items()}
    retained=a.output.read_bytes();value=life.privacy_check(retained,pe)
    inputs=[str(getattr(a,name)) for name in ('binary','focused','slot','support','state')]
    with tempfile.TemporaryDirectory(prefix='r35c-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(fixture.__file__)),*inputs,str(output)],check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x54a112,5)+3]^=1
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:fixture.extract(specimen))]
    for group in fixture.PINS:
        bad=copy.copy(a);setattr(bad,group,ChangedManifest(getattr(a,group)))
        probes.append(reject('changed '+group+' manifest','manifest mismatch '+group,lambda:fixture.extract(bad)))
    probes.append(reject('executed wrong date value','complete selector globals mismatch',lambda:fixture.produce(bytes(changed),decoded)))
    altered=bytearray(pe);altered[life.offset(pe,0x453c3d,2)+1]=19
    probes.append(reject('executed missing callback','complete selector globals mismatch',lambda:fixture.produce(bytes(altered),decoded)))
    heap=bytearray(pe);heap[life.offset(pe,0x94bf41,2)+1]=1
    probes.append(reject('executed wrong heap flags','next heap arguments mismatch',lambda:fixture.produce(bytes(heap),decoded)))
    native=life.rows((a.support/'0054a110.asm').read_bytes());native[0x54a112]='MOV dword ptr [EAX],0x28'
    probes.append(reject('resealed date store width','PE/native operand mismatch',lambda:life.compare([decoded[0x54a112]],native)))
    fragment=pe[life.offset(pe,0x84be20,32):life.offset(pe,0x84be20,32)+32]
    probes.append(reject('raw private fragment','private fragment in compressed evidence',lambda:life.privacy_check(retained+fragment,pe)))
    for label,hidden_value in (('hex',fragment.hex()),('base64',base64.b64encode(fragment).decode())):
        hidden=copy.deepcopy(value);hidden['private_fragment']=hidden_value
        probes.append(reject(label+' private fragment','private fragment in expanded evidence',lambda:life.privacy_check(life.pack(hidden),pe)))
    probes.append(reject('oversized expansion','expanded evidence size limit',lambda:life.privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    samples=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)] for start,size in life.RANGES.items()]
    pos=life.offset(pe,0x9e7f28,1);samples.append(pe[pos:pe.index(b'\0',pos)])
    forms=[form for sample in samples for form in (sample,sample.hex().encode(),base64.b64encode(sample))]
    for name in FILES:life.need(not any(form in Path(name).read_bytes() for form in forms),'private code/source in task file '+name)
    result={'unit':'R35-C','status':'passed','specimen_sha256':life.SPECIMEN,'evidence_sha256':life.sha(retained),
        'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),'compressed_bytes':len(retained),
        'expanded_canonical_bytes':len(life.compact(value))+1,'coverage':value['oracle']['coverage'],
        'normal_optimized_evidence':'byte-identical original-instruction regeneration',
        'native_operand_instructions':sum(r['instructions'] for r in sites['ranges'] if r['validation']=='PE/native operands'),
        'pe_only_instructions':sum(r['instructions'] for r in sites['ranges'] if r['validation']=='pinned PE decoding only'),
        'negative_probes':probes,'privacy':'compressed and bounded expanded evidence plus task files scanned for raw/hex/base64 code/source samples',
        'limits':fixture.SCOPE}
    a.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R35-C','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':main()
