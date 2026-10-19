#!/usr/bin/env python3
"""R36-C original regeneration and integrity/privacy probes, also under -O."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import extract_action33_selector_state_36 as selector
import extract_action33_lifecycle_31 as life
from verify_action33_slot_32 import MemoryFile,ChangedManifest,reject

FILES=('reports/action33-selector-state-36.md','scripts/extract_action33_selector_state_36.py',
       'scripts/verify_action33_selector_state_36.py','scripts/check-action33-selector-state-36.mjs')


class ChangedExport:
    def __init__(self,folder):self.folder=folder
    def __truediv__(self,name):
        return MemoryFile((self.folder/name).read_bytes()+b' ') if name=='0084b940.asm' else self.folder/name


def source_literal(pe):
    pos=life.offset(pe,0xa8278c,1)
    return pe[pos:pe.index(b'\0',pos)]


def private_forms(pe):
    samples=[]; unpadded=[]
    for start,(end,_,_) in selector.RANGES.items():
        length=end-start
        offset=life.offset(pe,start,length)
        block=pe[offset:offset+length]
        life.need(len(block)==length,'incomplete private range')
        samples.extend(block[i:i+32] for i in range(max(1,length-31)))
        width=min(30,length);width-=width%3
        if width:unpadded.extend(block[i:i+width] for i in range(length-width+1))
    source=source_literal(pe);life.need(len(source)>=16,'incomplete constructor source literal')
    samples.append(source)
    forms=[form for sample in samples for form in (sample,sample.hex().encode(),base64.b64encode(sample))]
    # A 32-byte sample encodes with '=' padding and does not occur inside a
    # longer base64 string. Thirty-byte windows have no padding, so one window
    # from every aligned position is present in any longer encoded excerpt.
    unpadded.extend(source[i:i+30] for i in range(len(source)-29))
    forms.extend(base64.b64encode(sample) for sample in unpadded)
    # JSON escapes path separators; scanning that representation also rejects
    # a plain source-text property in the expanded evidence.
    forms.append(json.dumps(source.decode('ascii'))[1:-1].encode())
    return forms


def privacy_check(raw,pe):
    life.need(len(raw)<=300000,'compressed evidence size limit')
    forms=private_forms(pe)
    life.need(not any(form in raw for form in forms),'private fragment in compressed evidence')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:expanded=stream.read(2000001)
    life.need(len(expanded)<=2000000,'expanded evidence size limit')
    life.need(not any(form in expanded for form in forms),'private fragment in expanded evidence')
    value=json.loads(expanded)
    life.need(life.pack(value)==raw,'noncanonical evidence gzip/JSON')
    return value


def main():
    parser=selector.parser();parser.add_argument('receipt',type=Path);a=parser.parse_args()
    pe,decoded,sites=selector.extract(a)
    retained=a.output.read_bytes();value=privacy_check(retained,pe)
    inputs=[str(getattr(a,name)) for name in ('binary','native','state')]
    with tempfile.TemporaryDirectory(prefix='r36c-check-') as directory:
        output=Path(directory)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(selector.__file__)),*inputs,str(output)],check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x81ba8d,10)+6]=0
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:selector.extract(specimen))]
    for group in selector.PINS:
        bad=copy.copy(a);setattr(bad,group,ChangedManifest(getattr(a,group)))
        probes.append(reject('changed '+group+' manifest','manifest mismatch '+group,lambda:selector.extract(bad)))
    bad=copy.copy(a);bad.native=ChangedExport(a.native)
    probes.append(reject('changed native export','native file mismatch',lambda:selector.extract(bad)))
    native=life.rows((a.native/'0084b940.asm').read_bytes());native[0x84b946]='MOV AL,byte ptr [0x00dd7118]'
    probes.append(reject('resealed constructor global width','PE/native operand mismatch',lambda:life.compare([decoded[0x84b946]],native)))
    probes.append(reject('executed wrong flag value','complete nonstack mismatch selector_globals',lambda:selector.produce(bytes(changed),decoded)))
    heap=bytearray(pe);heap[life.offset(pe,0x944ee8,2)+1]=1
    probes.append(reject('executed wrong heap flags','outgoing OS arguments mismatch',lambda:selector.produce(bytes(heap),decoded)))
    caller=bytearray(pe);caller[life.offset(pe,0x829dfc,2)+1]=32
    probes.append(reject('executed wrong receiver allocation size','outgoing OS arguments mismatch',lambda:selector.produce(bytes(caller),decoded)))
    drive=bytearray(pe);drive[life.offset(pe,0x84b96b,5)+1]=201
    probes.append(reject('executed wrong drive buffer length','outgoing OS arguments mismatch',lambda:selector.produce(bytes(drive),decoded)))
    fragment=pe[life.offset(pe,0x84b940,32):life.offset(pe,0x84b940,32)+32]
    probes.append(reject('raw private fragment','private fragment in compressed evidence',lambda:privacy_check(retained+fragment,pe)))
    for label,hidden_value in (('hex',fragment.hex()),('base64',base64.b64encode(fragment).decode())):
        hidden=copy.deepcopy(value);hidden['private_fragment']=hidden_value
        probes.append(reject(label+' private fragment','private fragment in expanded evidence',lambda:privacy_check(life.pack(hidden),pe)))
    later=pe[life.offset(pe,0x84b9c0,32):life.offset(pe,0x84b9c0,32)+32]
    probes.append(reject('later raw private fragment','private fragment in compressed evidence',lambda:privacy_check(retained+later,pe)))
    for label,hidden_value in (('hex',later.hex()),('base64',base64.b64encode(later).decode())):
        hidden=copy.deepcopy(value);hidden['private_fragment']=hidden_value
        probes.append(reject('later '+label+' private fragment','private fragment in expanded evidence',lambda:privacy_check(life.pack(hidden),pe)))
    for width in (33,48,64,96):
        longer=pe[life.offset(pe,0x84b9c0,width):life.offset(pe,0x84b9c0,width)+width]
        hidden=copy.deepcopy(value);hidden['private_fragment']=base64.b64encode(longer).decode()
        probes.append(reject('later base64 '+str(width)+'-byte fragment','private fragment in expanded evidence',lambda:privacy_check(life.pack(hidden),pe)))
    source=source_literal(pe)
    probes.append(reject('raw constructor source in container','private fragment in compressed evidence',lambda:privacy_check(retained+source,pe)))
    for label,hidden_value in (('plain JSON',source.decode('ascii')),('hex',source.hex()),('base64',base64.b64encode(source).decode())):
        hidden=copy.deepcopy(value);hidden['private_source']=hidden_value
        probes.append(reject(label+' constructor source in expanded evidence','private fragment in expanded evidence',lambda:privacy_check(life.pack(hidden),pe)))
    probes.append(reject('oversized expansion','expanded evidence size limit',lambda:privacy_check(life.pack({'padding':'X'*2000001}),pe)))
    forms=private_forms(pe)
    for name in FILES:life.need(not any(form in Path(name).read_bytes() for form in forms),'private code/source in task file '+name)
    result={'unit':'R36-C','status':'passed','specimen_sha256':life.SPECIMEN,'evidence_sha256':life.sha(retained),
        'expanded_canonical_sha256':life.sha(life.compact(value)+b'\n'),'compressed_bytes':len(retained),
        'expanded_canonical_bytes':len(life.compact(value))+1,'coverage':value['oracle']['coverage'],
        'normal_optimized_evidence':'byte-identical original-instruction regeneration',
        'native_operand_instructions':sum(r['instructions'] for r in sites['ranges'] if r['validation']=='PE/native operands'),
        'pe_only_instructions':sum(r['instructions'] for r in sites['ranges'] if r['validation']=='pinned PE decoding only'),
        'source_literal':{'address':'00a8278c','bytes':len(source),'sha256':life.sha(source)},
        'negative_probes':probes,'privacy':'compressed and bounded expanded evidence plus task files scanned for overlapping 32-byte raw/hex and unpadded 30-byte base64 samples across each range and complete constructor source literal, including JSON-escaped source text',
        'limits':selector.SCOPE}
    a.receipt.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R36-C','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__':main()
