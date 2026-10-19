#!/usr/bin/env python3
"""Reproduce R34-B evidence, reject altered inputs, and scan retained output."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import extract_action33_contract_34 as contract
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,ChangedManifest,reject

FILES=('reports/action33-contract-34.md','scripts/extract_action33_contract_34.py',
       'scripts/verify_action33_contract_34.py','scripts/check-action33-contract-34.mjs')


def main():
    p=contract.parser();p.add_argument('receipt',type=Path);a=p.parse_args()
    pe,decoded,sites=contract.extract(a)
    retained=a.output.read_bytes();value=life.privacy_check(retained,pe)
    life.need(value=={'sites':sites,'oracle':contract.produce(pe,decoded)},
              'retained evidence differs from original execution')
    inputs=[str(getattr(a,name)) for name in
            ('binary','state','staff','focused','support','exports25','slot','owner','database')]
    with tempfile.TemporaryDirectory(prefix='r34b-check-') as folder:
        target=Path(folder)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(contract.__file__)),
                            *inputs,str(target),str(a.contract_export)],
                           check=True,capture_output=True)
            life.need(target.read_bytes()==retained,'normal/-O retained evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x4cf624,6)+2]^=4
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.state=ChangedManifest(a.state)
    export=copy.copy(a)
    with tempfile.TemporaryDirectory(prefix='r34b-export-') as folder:
        path=Path(folder)/'004cf5f0.asm'
        path.write_bytes(a.contract_export.read_bytes()+b'\n')
        export.contract_export=path
        probes=[reject('changed specimen','pinned specimen mismatch',lambda:contract.extract(specimen)),
            reject('changed state manifest','manifest mismatch state',lambda:contract.extract(manifest)),
            reject('changed contract export','contract export mismatch',lambda:contract.extract(export))]
    altered=bytearray(pe);altered[life.offset(pe,0x8297fc,6)+2]^=4
    setup=copy.copy(a);setup.binary=MemoryFile(altered)
    probes.append(reject('changed setup global store','pinned specimen mismatch',lambda:contract.extract(setup)))
    # Failed inherited extractor probes reset its mutable admitted-range map.
    pe,decoded,_=contract.extract(a)
    # Execute changed original bytes under the unchanged decoded inventory to
    # ensure the semantic stride guard is independent of the native listing.
    modified=bytearray(pe);modified[life.offset(pe,0x4cf61c,3)+2]=0x8c
    probes.append(reject('executed wrong auxiliary stride','source-ID auxiliary stride changed',
                         lambda:contract.produce(bytes(modified),decoded)))
    fragment=pe[life.offset(pe,0x4cf5f0,32):life.offset(pe,0x4cf5f0,32)+32]
    probes.append(reject('raw private fragment','private fragment in compressed evidence',
                         lambda:life.privacy_check(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment','private fragment in expanded evidence',
                         lambda:life.privacy_check(life.pack(hidden),pe)))
    probes.append(reject('excessive expansion','expanded evidence size limit',
                         lambda:life.privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    samples=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)]
             for start,size in life.RANGES.items()]
    samples.append(pe[life.offset(pe,0x4cf5f0,32):life.offset(pe,0x4cf5f0,32)+32])
    forms=[v for sample in samples for v in (sample,sample.hex().encode(),base64.b64encode(sample))]
    for name in FILES:
        data=Path(name).read_bytes()
        life.need(not any(sample in data for sample in forms),'private code in task file '+name)
    result={'unit':'R34-B','status':'passed','specimen_sha256':life.SPECIMEN,
      'evidence_sha256':life.sha(retained),'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'compressed_bytes':len(retained),'expanded_canonical_bytes':len(life.compact(value))+1,
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'compared_instructions':sum(r['instructions'] for r in sites['selected_ranges']
                                  if r['all_native_operands_match']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded bytes plus authored files scanned for raw/hex/base64 code samples',
      'limits':contract.SCOPE}
    a.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R34-B','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':main()
