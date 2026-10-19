#!/usr/bin/env python3
"""Check R29-A retained evidence contains only synthetic inputs, effects and digests."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

SITES_SHA256='4692c12744e771684bc947871927ff47be2e26aeb3e25d0e0424243aeba13703'
ORACLE_SHA256='17c7fd897a832ceb746931870949ad6deb277129c5f87c418609a4229a690ea5'
CANONICAL_HEADER=bytes.fromhex('1f8b08000000000002ff')

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def parse_canonical(packed):
    need(len(packed)<200000 and packed[:10]==CANONICAL_HEADER and sha(packed)==ORACLE_SHA256,
         'noncanonical retained gzip envelope')
    source=gzip.decompress(packed)
    need(len(source)<5000000,'expanded oracle unexpectedly large')
    oracle=json.loads(source)
    need(source==json.dumps(oracle,separators=(',',':')).encode('utf-8'),
         'noncanonical compact JSON payload')
    return oracle

def check(sites_path,oracle_path):
    static=sites_path.read_bytes();packed=oracle_path.read_bytes()
    need(len(static)<50000 and sha(static)==SITES_SHA256,'site evidence hash mismatch')
    sites=json.loads(static);oracle=parse_canonical(packed)
    need(sites['specimen_sha256']==oracle['specimen_sha256'] and
         sites['body_sha256']==oracle['body_sha256'] and sites['entry_va']==oracle['entry_va']=='006ce110',
         'provenance mismatch')
    need(oracle['function_cases']==315 and len(oracle['cases'])==315 and
         oracle['covered_instruction_starts']==sites['instruction_starts'],'scope or instruction coverage mismatch')
    need({tuple(v) for v in oracle['covered_local_edges']}=={tuple(v) for v in sites['edges']},'CFG edge coverage mismatch')
    need(oracle['scope'].startswith('synthetic disjoint stable'),'oracle input origin mismatch')
    regnames={'eax','ebx','ecx','edx','esi','edi','ebp','esp'}
    seen=set()
    for row in oracle['cases']:
        need(set(row)=={'input','initial','final','trace','effects','memory_sha256'},'unexpected row payload')
        a,b,s=row['input'];need(type(a)==type(b)==type(s)==int and
             ((0<=a<10 and 0<=b<10) or (10<=a<15 and b==a)) and s in (0,1,2),'input schedule mismatch')
        seen.add((a,b,s))
        for label in ('initial','final'):
            regs=row[label]
            need(set(regs)==regnames and all(type(v)==int and 0<=v<=0xffffffff for v in regs.values()),'register payload mismatch')
        need(0<len(row['trace'])<3000 and all(v in sites['instruction_starts'] for v in row['trace']),'trace payload mismatch')
        for event in row['effects']:
            need(type(event)==list and len(event) in (3,4) and event[0] in ('read','write') and
                 re.fullmatch(r'[0-9a-f]{8}',event[1]) and event[2] in (1,2,4) and
                 (len(event)==3 if event[0]=='read' else type(event[3])==int and 0<=event[3]<2**(8*event[2])),
                 'effect payload mismatch')
        need(len(row['memory_sha256'])==3 and all(re.fullmatch(r'[0-9a-f]{64}',v) for v in row['memory_sha256']),
             'raw memory or malformed digest retained')
    need(len(seen)==315,'case schedule duplicate or missing')
    mutations=[]
    for osbyte in (0x03,0x0a):
        changed=packed[:9]+bytes([osbyte])+packed[10:]
        need(gzip.decompress(changed)==gzip.decompress(packed),'OS-byte probe setup failed')
        try:parse_canonical(changed)
        except ValueError:mutations.append(f'gzip OS byte {osbyte:02x} rejected')
        else:raise ValueError('alternate gzip OS envelope admitted')
    changed=bytearray(packed);changed[3]|=8
    with_name=bytes(changed[:10])+b'hidden-name\0'+bytes(changed[10:])
    need(gzip.decompress(with_name)==gzip.decompress(packed),'FNAME probe setup failed')
    try:parse_canonical(with_name)
    except ValueError:mutations.append('optional gzip filename rejected')
    else:raise ValueError('optional gzip filename admitted')
    payload=gzip.decompress(packed)
    with_space=gzip.compress(payload+b' ',compresslevel=9,mtime=0)
    with_space=with_space[:9]+b'\xff'+with_space[10:]
    try:parse_canonical(with_space)
    except ValueError:mutations.append('appended JSON whitespace rejected')
    else:raise ValueError('noncanonical JSON admitted')
    return {'unit':'R29-A','status':'passed','sites_sha256':sha(static),'oracle_sha256':sha(packed),
            'case_count':315,'retained_memory':'three SHA-256 digests per case; no raw match/table/stack memory',
            'retained_inputs':'synthetic mode IDs and selector only','compressed_bytes':len(packed),
            'negative_mutations':mutations}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('sites','oracle','output'):p.add_argument(name,type=Path)
    a=p.parse_args();a.output.write_text(json.dumps(check(a.sites,a.oracle),indent=2)+'\n',encoding='utf-8',newline='\n')
