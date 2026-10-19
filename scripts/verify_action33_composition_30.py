#!/usr/bin/env python3
"""R30-C normal/-O reproduction, provenance mutations and public-payload checks."""
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from emulate_action33_composition_30 import generate,PREFIX_ORACLE,PREFIX_SCRIPT,PREFIX_SITES
from emulate_action33_prefix_30 import need,sha,compact,packed,decode,make_case
from extract_action33_prefix_30 import parser,compare,rows


def keys(value,expected):
    need(set(value)==set(expected.split()),'unexpected public fields')


def unsigned(value):
    return type(value)==int and 0<=value<=0xffffffff


def random_state(value):
    keys(value,'cursorIndex offset crtState')
    need(all(unsigned(v) for v in value.values()) and value['cursorIndex']<51000 and value['offset']<=65535,
         'unexpected RNG state')


def public_payload(blob):
    need(blob[:10]==bytes.fromhex('1f8b08000000000002ff') and len(blob)<300000,'noncanonical gzip envelope')
    raw=gzip.decompress(blob);need(len(raw)<2500000,'public oracle unexpectedly large')
    value=json.loads(raw)
    need(raw==compact(value)+b'\n' and packed(value)==blob,'noncanonical public payload')
    keys(value,'unit schema_version specimen_sha256 prefix_oracle_sha256 prefix_emulator_sha256 prefix_sites_sha256 start stop_before cases scope first_missing_entry_callee coverage')
    need(value['unit']=='R30-C' and value['start']=='007022fd' and value['stop_before']=='007024b4','scope changed')
    need(len(value['cases'])==160,'case count changed')
    for n,row in enumerate(value['cases']):
        keys(row,'case checkpoint selector_memory game_writes calls draws result final_rng final_memory_sha256')
        need(row['case']==make_case(n),'not the fixed synthetic input schedule')
        checkpoint=row['checkpoint'];keys(checkpoint,'input rng patches match_sha256 positions_sha256')
        keys(checkpoint['input'],'match shooter action mode zeroLocalByte marker260 marker375 precisionBits')
        need(all(type(v)==int and 0<=v<=0xffffffff for v in checkpoint['input'].values()),'unexpected checkpoint scalar')
        random_state(checkpoint['rng'])
        for offset,v in checkpoint['patches']:
            need(offset in (0x8d4c,0x8d4d,0x8d4e) and type(v)==int and 0<=v<256,'unexpected prior-producer bytes')
        for group in ('selector_memory','game_writes'):
            for kind,address,size,v in row[group]:
                a=int(address,16)
                need(kind in ('read','write') and size in (1,2,4) and type(v)==int and 0<=v<2**(size*8),
                     'invalid synthetic operand')
                need(any(base<=a and a+size<=base+length for base,length in ((0x4100000,0x10000),(0x4300000,0x1000))),
                     'non-synthetic retained operand')
        keys(row['final_memory_sha256'],'match positions random_table grid')
        for digest in row['final_memory_sha256'].values():
            need(type(digest)==str and len(digest)==64 and set(digest)<=set('0123456789abcdef'),'unexpected raw memory')
        for call in row['calls']:
            keys(call,'site target receiver args')
            need(call['target'] in ('006ce110','0090cfc0','00700420','006c38c0'),'unexpected retained call')
            need(call['receiver'] is None or unsigned(call['receiver']),'unexpected call receiver')
            need(all(type(v)==int and -65535<=v<=0xffffffff for v in call['args']),'unexpected call arguments')
        for draw in row['draws']:
            keys(draw,'site bound value initial final')
            for label in ('initial','final'):
                random_state(draw[label])
            need(type(draw['bound'])==type(draw['value'])==int and abs(draw['bound'])<=65535 and abs(draw['value'])<=65535,
                 'unexpected draw scalars')
        keys(row['result'],'keeper variant responseWord positionFlag fallbackFlag marker260 marker375 eligible path outgoingArgumentDwords')
        need(row['result']['path'] in ('rejected','retained','weighted','redrawn') and type(row['result']['eligible'])==bool,
             'unexpected semantic result')
        need(all(unsigned(v) for k,v in row['result'].items() if k not in ('eligible','path','outgoingArgumentDwords')),
             'unexpected result scalars')
        need(len(row['result']['outgoingArgumentDwords'])==5 and
             all(type(v)==int and 0<=v<=0xffffffff for v in row['result']['outgoingArgumentDwords']),'bad outgoing argument frame')
        random_state(row['final_rng'])
    return value


def rejects(action,text):
    try:action()
    except (ValueError,RuntimeError) as error:
        need(text in str(error),'wrong rejection: '+str(error));return text
    raise ValueError('mutation admitted: '+text)


def verify(a):
    root=Path(__file__).resolve().parents[1];(root/'results').mkdir(parents=True,exist_ok=True)
    retained=(root/'evidence/action33-composition-30-oracle.bin').read_bytes();oracle=public_payload(retained)
    original=a.binary
    with tempfile.TemporaryDirectory(prefix='composition-30-',dir=root/'results') as folder:
        temporary=Path(folder);common=[str(a.binary)]
        for name in ('fresh','r29','preflight','caller','runtime'):common+=['--'+name,str(getattr(a,name))]
        for label,flags in (('normal',[]),('optimized',['-O'])):
            output=temporary/(label+'.bin')
            subprocess.run([sys.executable,*flags,str(root/'scripts/emulate_action33_composition_30.py'),*common,'--output',str(output)],check=True,capture_output=True)
            need(output.read_bytes()==retained,'normal/-O original-entry evidence changed')
        data=bytearray(a.binary.read_bytes());data[0x3022fd]^=1
        bad=temporary/'changed.exe';bad.write_bytes(data);a.binary=bad
        try:changed=rejects(lambda:generate(a),'specimen size/SHA-256 mismatch')
        finally:a.binary=original
        native=rows(a.r29/'006ce110.asm');native[0x6ce110]='MOV EAX,dword ptr [ECX + 0xf59f]'
        instructions,_=decode(original.read_bytes())
        operand=rejects(lambda:compare({k:v for k,v in instructions.items() if 0x6ce110<=k<0x6ce304},native),'native operand mismatch 006ce110')
        copy=temporary/'exports';shutil.copytree(a.r29,copy)
        path=copy/'006ce110.asm';path.write_bytes(path.read_bytes()+b'\n')
        old=a.r29;a.r29=copy
        try:native_file=rejects(lambda:generate(a),'native file digest mismatch')
        finally:a.r29=old
        whitespace=packed(oracle)
        source=gzip.decompress(whitespace)+b' '
        variant=gzip.compress(source,compresslevel=9,mtime=0);variant=variant[:9]+b'\xff'+variant[10:]
        canonical=rejects(lambda:public_payload(variant),'noncanonical public payload')
        variant=retained[:9]+b'\x03'+retained[10:]
        envelope=rejects(lambda:public_payload(variant),'noncanonical gzip envelope')
    return {'unit':'R30-C','status':'passed','oracle_sha256':sha(retained),
      'prefix_oracle_sha256':PREFIX_ORACLE,'prefix_emulator_sha256':PREFIX_SCRIPT,'prefix_sites_sha256':PREFIX_SITES,
      'coverage':oracle['coverage'],'normal_optimized':'both original-entry regenerations equal retained bytes',
      'negative_checks':{'changed_PE':changed,'independent_native_operand':operand,'changed_native_file':native_file,
        'appended_json_whitespace':canonical,'alternate_gzip_envelope':envelope},
      'privacy':'fixed synthetic schedule, three allowed prior-producer byte locations and synthetic operand values; full regions retained only as digests',
      'scope':'supplied original-produced 007022fd checkpoint through 007024b4; no full-entry, machine-stack or shot-result claim'}


if __name__=='__main__':
    a=parser().parse_args();result=verify(a);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');print(result['status'],result['coverage'])
