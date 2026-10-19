#!/usr/bin/env python3
"""R36-B private-input regeneration, semantic negatives and bounded privacy."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_contract_row_36 as rows
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,reject

FILES=('scripts/extract_action33_contract_row_36.py','scripts/verify_action33_contract_row_36.py',
 'scripts/check-action33-contract-row-36.mjs','reports/action33-contract-row-36.md')


class ChangedManifest:
    def __init__(self,folder):self.folder=folder
    def __truediv__(self,name):
        raw=(self.folder/name).read_bytes()
        return MemoryFile(raw+b' ') if name in ('manifest.json','EXPORT-MANIFEST.json') else self.folder/name


def samples(pe):
    spans=[(start,end-start) for start,(end,_,_) in rows.NATIVE.items()]+list(rows.PE_ONLY.items())
    raw=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)] for start,size in spans]
    return [v for fragment in raw for v in (fragment,fragment.hex().encode(),base64.b64encode(fragment))]


def privacy(raw,pe):
    life.need(len(raw)<=300000,'compressed evidence size limit');forms=samples(pe)
    life.need(not any(v in raw for v in forms),'private fragment in compressed evidence')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:expanded=stream.read(2000001)
    life.need(len(expanded)<=2000000,'expanded evidence size limit')
    life.need(not any(v in expanded for v in forms),'private fragment in expanded evidence')
    value=json.loads(expanded);life.need(life.pack(value)==raw,'noncanonical evidence');return value


def main():
    p=rows.parser();p.add_argument('receipt',type=Path);a=p.parse_args()
    pe,decoded,sites=rows.extract(a);retained=a.output.read_bytes();value=privacy(retained,pe)
    with tempfile.TemporaryDirectory(prefix='r36b-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(rows.__file__)),str(a.binary),str(a.contracts),str(a.support),str(a.state),str(output)],check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x4c75a0,3)+2]=3
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:rows.extract(specimen))]
    for name in ('contracts','support','state'):
        modified=copy.copy(a);setattr(modified,name,ChangedManifest(getattr(a,name)))
        probes.append(reject('changed '+name+' manifest','manifest mismatch',lambda:rows.extract(modified)))
    probes.append(reject('executed wrong row allocation stride','complete stack mismatch',lambda:rows.produce(bytes(changed),decoded)))
    changed=bytearray(pe);changed[life.offset(pe,0x85e44b,3)+2]=8
    probes.append(reject('executed wrong temporary store','complete stack mismatch',lambda:rows.produce(bytes(changed),decoded)))
    changed=bytearray(pe);changed[life.offset(pe,0x4c79dd,5)+1]=0xc9
    probes.append(reject('executed wrong reserve capacity','complete nonstack memory mismatch manager',lambda:rows.produce(bytes(changed),decoded)))
    changed=bytearray(pe);changed[life.offset(pe,0x4c7840,2)+1]=5
    probes.append(reject('executed wrong eligible class','unsupported executed call',lambda:rows.produce(bytes(changed),decoded)))
    native=life.rows((a.contracts/'004c7560.asm').read_bytes());native[0x4c788e]='MOV word ptr [EDX + ECX*0x1],AX'
    probes.append(reject('resealed row-index store width','PE/native operand mismatch',lambda:life.compare([decoded[0x4c788e]],native)))
    fragment=pe[life.offset(pe,0x85e410,32):life.offset(pe,0x85e410,32)+32]
    probes.append(reject('raw private fragment','private fragment in compressed evidence',lambda:privacy(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment','private fragment in expanded evidence',lambda:privacy(life.pack(hidden),pe)))
    hidden['private_fragment']=base64.b64encode(fragment).decode()
    probes.append(reject('base64 private fragment','private fragment in expanded evidence',lambda:privacy(life.pack(hidden),pe)))
    probes.append(reject('excessive expansion','expanded evidence size limit',lambda:privacy(life.pack({'padding':'X'*2000001}),pe)))
    for name in FILES:life.need(not any(v in Path(name).read_bytes() for v in samples(pe)),'private code in task file '+name)
    receipt={'unit':'R36-B','status':'passed','specimen_sha256':life.SPECIMEN,'evidence_sha256':life.sha(retained),
      'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'native_compared_instructions':sum(r['instructions'] for r in sites['selected_ranges'] if r['native_operands_match']),
      'pe_only_decoded_instructions':sum(r['instructions'] for r in sites['selected_ranges'] if not r['native_operands_match']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded evidence plus authored files scanned for raw/hex/base64 samples','scope':rows.SCOPE}
    a.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(receipt))


if __name__=='__main__':main()
