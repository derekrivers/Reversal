#!/usr/bin/env python3
"""Regenerate R35-B in normal/-O, reject mutations and scan bounded payloads."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_aux_35 as aux
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,ChangedManifest,reject

FILES=('scripts/extract_action33_aux_35.py','scripts/verify_action33_aux_35.py',
       'scripts/check-action33-aux-35.mjs','reports/action33-aux-35.md')


def samples(pe):
    spans=[(start,end-start) for start,(end,_) in aux.RANGES.items()]+list(aux.PE_ONLY.items())
    raw=[pe[life.offset(pe,start,min(32,size)):life.offset(pe,start,min(32,size))+min(32,size)] for start,size in spans]
    return [v for fragment in raw for v in (fragment,fragment.hex().encode(),base64.b64encode(fragment))]


def privacy(raw,pe):
    life.need(len(raw)<=300000,'compressed evidence size limit')
    forms=samples(pe)
    life.need(not any(v in raw for v in forms),'private fragment in compressed evidence')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:expanded=stream.read(2000001)
    life.need(len(expanded)<=2000000,'expanded evidence size limit')
    life.need(not any(v in expanded for v in forms),'private fragment in expanded evidence')
    value=json.loads(expanded);life.need(life.pack(value)==raw,'noncanonical evidence')
    return value


def main():
    p=aux.parser();p.add_argument('receipt',type=Path);a=p.parse_args()
    pe,decoded,sites=aux.extract(a);retained=a.output.read_bytes();value=privacy(retained,pe)
    with tempfile.TemporaryDirectory(prefix='r35b-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(aux.__file__)),str(a.binary),str(a.state),str(output)],check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x8284a7,3)+2]=3
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.state=ChangedManifest(a.state)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:aux.extract(specimen)),
      reject('changed state manifest','state manifest mismatch',lambda:aux.extract(manifest)),
      reject('executed wrong allocation stride','allocation complete stack mismatch',lambda:aux.produce(bytes(changed),decoded))]
    native=life.rows((a.state/'00828110.asm').read_bytes());native[0x828556]='MOV word ptr [ESI + 0x4],0xffff'
    probes.append(reject('resealed sentinel store width','PE/native operand mismatch',lambda:life.compare([decoded[0x828556]],native)))
    fragment=pe[life.offset(pe,0x82849a,32):life.offset(pe,0x82849a,32)+32]
    probes.append(reject('raw private fragment','private fragment in compressed evidence',lambda:privacy(retained+fragment,pe)))
    hidden=copy.deepcopy(value);hidden['private_fragment']=fragment.hex()
    probes.append(reject('hex private fragment','private fragment in expanded evidence',lambda:privacy(life.pack(hidden),pe)))
    hidden['private_fragment']=base64.b64encode(fragment).decode()
    probes.append(reject('base64 private fragment','private fragment in expanded evidence',lambda:privacy(life.pack(hidden),pe)))
    probes.append(reject('excessive expansion','expanded evidence size limit',lambda:privacy(life.pack({'padding':'X'*2000001}),pe)))
    for name in FILES:
        life.need(not any(v in Path(name).read_bytes() for v in samples(pe)),'private code in task file '+name)
    receipt={'unit':'R35-B','status':'passed','specimen_sha256':life.SPECIMEN,'evidence_sha256':life.sha(retained),
      'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),
      'normal_optimized_evidence':'byte-identical original-instruction regeneration',
      'native_compared_instructions':sum(r['instructions'] for r in sites['selected_ranges'] if r['native_operands_match']),
      'pe_only_decoded_instructions':sum(r['instructions'] for r in sites['selected_ranges'] if not r['native_operands_match']),
      'coverage':value['oracle']['coverage'],'negative_probes':probes,
      'privacy':'compressed and bounded expanded evidence plus authored files scanned for raw/hex/base64 samples','scope':aux.SCOPE}
    a.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(receipt))


if __name__=='__main__':main()
