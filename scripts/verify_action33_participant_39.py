#!/usr/bin/env python3
"""R39-B reproducibility, operand mutations and exhaustive excerpt privacy gates."""
import base64
import copy
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import extract_action33_participant_39 as unit
import extract_action33_lifecycle_31 as life

TASK_FILES=('scripts/extract_action33_participant_39.py','scripts/verify_action33_participant_39.py',
            'scripts/check-action33-participant-39.mjs','reports/action33-participant-39.md')


class MemoryFile:
    def __init__(self,raw): self.raw=raw
    def read_bytes(self): return self.raw


class ChangedManifest:
    def __init__(self,folder): self.folder=folder
    def __truediv__(self,name):
        return MemoryFile((self.folder/name).read_bytes()+b' ') if name=='manifest.json' else self.folder/name


def reject(label,gate,work):
    try: work()
    except ValueError as exc:
        life.need(gate in str(exc),'wrong negative gate '+label+': '+str(exc))
        return label
    raise ValueError('mutation admitted '+label)


def private_forms(pe):
    samples=set()
    for start,size in life.RANGES.items():
        raw=pe[life.offset(pe,start,size):life.offset(pe,start,size)+size]
        if len(raw)>=32:
            samples.update(raw[k:k+32] for k in range(len(raw)-31))
    pos=life.offset(pe,0x9e7f28,1);source=pe[pos:pe.index(b'\0',pos)]
    samples.update(source[k:k+32] for k in range(len(source)-31))
    forms=set()
    for sample in samples:
        forms.update((sample,sample.hex().encode(),sample.hex().upper().encode()))
        # Thirty complete bytes are forty padding-free characters; all three
        # alignments catch excerpts embedded inside a longer base64 payload.
        forms.update(base64.b64encode(sample[k:k+30]) for k in range(3))
    return forms,len(samples)


def scan(raw,forms,where):
    life.need(not any(fragment in raw for fragment in forms),'private fragment in '+where)


def privacy(raw,forms):
    life.need(len(raw)<=300000,'compressed evidence size limit')
    scan(raw,forms,'compressed evidence')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream: expanded=stream.read(2000001)
    life.need(len(expanded)<=2000000,'expanded evidence size limit')
    scan(expanded,forms,'expanded evidence')
    value=json.loads(expanded)
    life.need(life.pack(value)==raw,'noncanonical evidence gzip/JSON')
    return value


def main():
    parser=unit.parser();parser.add_argument('receipt',type=Path);a=parser.parse_args()
    pe,decoded,sites=unit.extract(a);retained=a.output.read_bytes()
    forms,windows=private_forms(pe);value=privacy(retained,forms)
    inputs=[str(getattr(a,k)) for k in ('binary','state','staff','focused','support','exports25','slot')]
    with tempfile.TemporaryDirectory(prefix='r39b-reproduction-') as folder:
        output=Path(folder)/'oracle.bin'
        for mode in ([],['-O']):
            subprocess.run([sys.executable,'-B',*mode,str(Path(unit.__file__)),*inputs,str(output)],
                           check=True,capture_output=True)
            life.need(output.read_bytes()==retained,'normal/-O retained evidence differs')
    changed=bytearray(pe);changed[life.offset(pe,0x94bf43,6)+2]^=4
    specimen=copy.copy(a);specimen.binary=MemoryFile(changed)
    manifest=copy.copy(a);manifest.slot=ChangedManifest(a.slot)
    probes=[reject('changed specimen','pinned specimen mismatch',lambda:unit.extract(specimen)),
            reject('changed inherited native manifest','slot manifest mismatch',lambda:unit.extract(manifest))]
    # The PE-only extension has explicit independent operand checks. Native
    # comparisons for inherited source ranges remain active separately.
    old=unit.OPERANDS[0x94bf43]
    try:
        unit.OPERANDS[0x94bf43]='push dword ptr [0xde4404]'
        probes.append(reject('changed authored heap operand','R39 authored operand mismatch',lambda:unit.extract(a)))
    finally: unit.OPERANDS[0x94bf43]=old
    unit.extract(a)
    probes.append(reject('executed wrong heap global','continuation ordered operand/source mismatch',
                         lambda:unit.produce(bytes(changed),decoded)))
    changed_mode=bytearray(pe);changed_mode[life.offset(pe,0x94bef6,5)+1]^=1
    probes.append(reject('executed wrong heap mode source','continuation ordered operand/source mismatch',
                         lambda:unit.produce(bytes(changed_mode),decoded)))
    bad_store=bytearray(pe);bad_store[life.offset(pe,0x6eaecb,3)+2]^=0x10
    probes.append(reject('executed wrong original participant store','R32 prefix continuity mismatch placement',
                         lambda:unit.produce(bytes(bad_store),decoded)))
    native=life.rows((a.slot/'006eada0.asm').read_bytes());native[0x6eadb2]='MOV word ptr [EAX + 0x27],CX'
    probes.append(reject('resealed inherited native width','PE/native operand mismatch',
                         lambda:life.compare([decoded[0x6eadb2]],native)))
    fragment=pe[life.offset(pe,0x62ab00+123,32):life.offset(pe,0x62ab00+123,32)+32]
    probes.append(reject('late raw private excerpt','private fragment in compressed evidence',
                         lambda:privacy(retained+fragment,forms)))
    for label,encoded in [('late lowercase hex',fragment.hex()),('late uppercase hex',fragment.hex().upper()),
                          ('embedded base64 alignment zero',base64.b64encode(fragment).decode()),
                          ('embedded base64 alignment one',base64.b64encode(b'X'+fragment+b'Y').decode()),
                          ('embedded base64 alignment two',base64.b64encode(b'XY'+fragment+b'Z').decode())]:
        hidden=copy.deepcopy(value);hidden['private_excerpt']=encoded
        probes.append(reject(label,'private fragment in expanded evidence',lambda:hidden and privacy(life.pack(hidden),forms)))
    probes.append(reject('excessive gzip expansion','expanded evidence size limit',
                         lambda:privacy(life.pack({'padding':'X'*2000001}),forms)))
    for name in TASK_FILES: scan(Path(name).read_bytes(),forms,'task file '+name)
    result={'unit':'R39-B','status':'passed','specimen_sha256':life.SPECIMEN,
            'oracle_sha256':life.sha(retained),'expanded_sha256':life.sha(life.compact(value)+b'\n'),
            'normal_optimized_regeneration':'byte-identical','coverage':value['oracle']['coverage'],
            'native_compared_instructions':sum(r['instructions'] for r in sites['ranges']),
            'pe_only_instructions':sum(r['instructions'] for r in sites['extra_ranges']),
            'privacy_windows':windows,'privacy_forms':len(forms),'negative_probes':probes,
            'limits':'separate synthetic entries; no resolver, Windows calls, initialized lookup object, TypeScript or live claim'}
    receipt=json.dumps(result,indent=2)+'\n';scan(receipt.encode(),forms,'validation receipt')
    a.receipt.write_text(receipt,encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R39-B','status':'passed','negative_probes':len(probes)}))


if __name__=='__main__': main()
