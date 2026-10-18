#!/usr/bin/env python3
"""R13-C compact static evidence; requires capstone==5.0.7, no game execution.

Reads the pinned PE and optional read-only checkpoint-12 exports. Retains hashes,
selected instruction sites and call targets; never writes native or bulk exports.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = 'fa2728212d3189f2a0ec9f4db14b2355b0da8457bc9bff091d5c2b442b38a489'
OWNED = [(0x8b23b0,182),(0x8b35a0,157),(0x8b3930,188),(0x8b3c50,230),(0x8b4cd0,212)]
SELECTED = {
    0x8b23b0: [0x8b23b8,0x8b23bf,0x8b23c1,0x8b23c2,0x8b23c7,0x8b23c9,
        0x8b23f4,0x8b2424,0x8b2436,0x8b243a,0x8b2442,0x8b2447,0x8b2449,0x8b244a,
        0x8b244c,0x8b244e,0x8b2451,0x8b2452,0x8b2454,0x8b2463],
    0x8b35a0: [0x8b35a0,0x8b35aa,0x8b35ab,0x8b35b0,0x8b35b2,0x8b360b,
        0x8b35db,0x8b361b,0x8b3620,0x8b3627,0x8b362c,0x8b362e,0x8b3630,0x8b363a],
    0x8b3930: [0x8b3930,0x8b3934,0x8b3940,0x8b3942,0x8b3945,0x8b3946,
        0x8b3948,0x8b394b,0x8b394d,0x8b3954,0x8b3956,0x8b3958,0x8b395b,
        0x8b395d,0x8b395f,0x8b3962,0x8b3965,0x8b396b,0x8b396e,0x8b3970,
        0x8b3973,0x8b397b,0x8b39a7,0x8b39d7,0x8b39e1,0x8b39e9],
    0x8b3c50: [0x8b3c50,0x8b3c5c,0x8b3c5e,0x8b3c60,0x8b3c61,0x8b3c69,
        0x8b3c6f,0x8b3c71,0x8b3c9a,0x8b3cca,0x8b3cdc,0x8b3ce2,0x8b3ce7,0x8b3ce9,
        0x8b3ceb,0x8b3cee,0x8b3cf6,0x8b3cf9,0x8b3d02,0x8b3d0b,0x8b3d0e,
        0x8b3d13,0x8b3d15,0x8b3d1b,0x8b3d1f,0x8b3d25,0x8b3d26,0x8b3d29,
        0x8b3d2b,0x8b3d35],
    0x8b4cd0: [0x8b4cd0,0x8b4cda,0x8b4cdc,0x8b4d05,0x8b4d0d,0x8b4d13,
        0x8b4d15,0x8b4d18,0x8b4d19,0x8b4d1b,0x8b4d1e,0x8b4d20,0x8b4d23,
        0x8b4d26,0x8b4d33,0x8b4d5f,0x8b4d8f,0x8b4d99,0x8b4da1],
}
# Dependency ranges provide instruction alignment only; they are not owned bodies.
CONTEXT = {
    (0x8b0a00,0x8b0b20): [0x8b0a8d,0x8b0a93,0x8b0a9a,0x8b0aa3,0x8b0aae,
        0x8b0ab6,0x8b0ab8,0x8b0abf,0x8b0ac8,0x8b0ad7,0x8b0adf,0x8b0ae6,
        0x8b0aec,0x8b0af2,0x8b0af3],
    (0x8b0b40,0x8b0bec): [0x8b0b68,0x8b0b6e,0x8b0b75,0x8b0b7a,0x8b0b85,
        0x8b0b87,0x8b0b92,0x8b0b97,0x8b0bc6,0x8b0bcc,0x8b0bcd,0x8b0bd3,
        0x8b0bd4,0x8b0bda],
    (0x8b0ec0,0x8b1061): [0x8b0ee9,0x8b0eee,0x8b0ef3,0x8b0ef8,0x8b0fef,
        0x8b0ff5,0x8b0ffb,0x8b1001,0x8b1006,0x8b100b,0x8b100d,0x8b100f,
        0x8b1011,0x8b1016,0x8b101c,0x8b1021,0x8b1028,0x8b102b,0x8b102e,
        0x8b1031,0x8b1034,0x8b1038,0x8b103d,0x8b104c],
    (0x8b1070,0x8b10c4): [0x8b1071,0x8b1073,0x8b1079,0x8b107b,0x8b107d,
        0x8b107e,0x8b1086,0x8b1090,0x8b109b,0x8b10a3,0x8b10bd,0x8b10c3],
    (0x8b2880,0x8b2bbd): [0x8b2885,0x8b288a,0x8b288e,0x8b28f1,0x8b28f2,
        0x8b28f4,0x8b28fa,0x8b2913,0x8b2915,0x8b293d,0x8b2943,0x8b2945,
        0x8b298d,0x8b2991,0x8b2b89,0x8b2bba],
    (0x945501,0x9455b2): [0x945505,0x945508,0x945513,0x945519,0x94551c,
        0x94551f,0x94553f,0x945560,0x94556c,0x94556d,0x94556f,0x945575,
        0x945597,0x94559a,0x94559c,0x94559d,0x9455a5,0x9455ab,0x9455ac],
    (0x9452ca,0x945333): [0x9452cf,0x9452d2,0x945321,0x945322,0x945324,0x94532a],
    (0x94a640,0x94a698): [0x94a640,0x94a644,0x94a64e,0x94a663,0x94a681,0x94a687],
}


def norm(text):
    text = text.lower().replace('movsd.rep','rep movsd')
    if text.startswith('rep movsd'):
        return 'rep movsd'
    if text.startswith('movsw'):
        return 'movsw'
    text = re.sub(r'\bjz\b','je',text)
    text = re.sub(r'\bjnz\b','jne',text)
    # Ghidra suppresses the redundant width in absolute EAX loads. Preserve all
    # other widths, including immediate-to-memory stores and byte comparisons.
    text = re.sub(r'\bmov eax,\[', 'mov eax,dword ptr [',text)
    text = re.sub(r'\b0x[0-9a-f]+\b', lambda m: str(int(m[0],16)),text)
    text = re.sub(r'\s+','',text)
    return text.replace('+0]',']').replace('*1]',']')


def extract(binary, native):
    assert capstone.__version__ == '5.0.7', 'requires capstone==5.0.7'
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA, 'wrong executable'
    pe = struct.unpack_from('<I',data,0x3c)[0]
    assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
    opt = pe+24
    assert struct.unpack_from('<H',data,opt)[0] == 0x10b
    base = struct.unpack_from('<I',data,opt+28)[0]
    count = struct.unpack_from('<H',data,pe+6)[0]
    size = struct.unpack_from('<H',data,pe+20)[0]
    sections = [struct.unpack_from('<8sIIII',data,opt+size+40*i) for i in range(count)]

    def offset(va, size=1):
        for _,_,rva,rawsize,raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= rawsize:
                return raw+delta
        raise ValueError(f'unbacked VA {va:x}')

    def raw(start,end):
        off = offset(start,end-start)
        return data[off:off+end-start]

    def string(va):
        off = offset(va)
        return data[off:data.index(b'\0',off)].decode('ascii')

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    def decode(start,end):
        rows = list(md.disasm(raw(start,end),start))
        assert rows and rows[0].address == start and rows[-1].address+rows[-1].size == end
        assert sum(i.size for i in rows) == end-start
        return rows
    def row(ins):
        return (ins.mnemonic+' '+ins.op_str).strip()

    manifest = None
    if native:
        manifest_path = native/'EXPORT-MANIFEST.json'
        assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == MANIFEST_SHA
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest['files']:
            file = native/entry['name']
            assert len(file.read_bytes()) == entry['bytes']
            assert hashlib.sha256(file.read_bytes()).hexdigest() == entry['sha256']
    bodies = []
    for start,size in OWNED:
        ins = decode(start,start+size)
        mapping = {i.address:row(i) for i in ins}
        receipt = None
        if native:
            name = f'{start:08x}'
            listing = {int(l[:8],16):l[10:] for l in (native/(name+'.asm')).read_text().splitlines() if l}
            left = {a:norm(t) for a,t in mapping.items()}
            right = {a:norm(t) for a,t in listing.items()}
            assert left == right, [(hex(a),left.get(a),right.get(a)) for a in left.keys()|right.keys() if left.get(a)!=right.get(a)]
            receipt = {'all_instructions_match':True,
                'incoming_call_sites':[l.split()[0] for l in (native/(name+'.refs')).read_text().splitlines()],
                'export_sha256':{name+ext:hashlib.sha256((native/(name+ext)).read_bytes()).hexdigest() for ext in ('.asm','.c','.refs')}}
        bodies.append({'entry_va':f'{start:08x}','end_exclusive_va':f'{start+size:08x}',
            'file_offset':f'{offset(start,size):08x}','length_bytes':size,
            'body_sha256':hashlib.sha256(raw(start,start+size)).hexdigest(),
            'instruction_count':len(ins),'selected_sites':{f'{a:08x}':mapping[a] for a in SELECTED[start]},
            'all_direct_calls':[{'site':f'{i.address:08x}','target':i.op_str} for i in ins if i.mnemonic=='call'],
            'native_comparison':receipt})
    context = []
    for (start,end),sites in CONTEXT.items():
        ins = decode(start,end)
        mapping = {i.address:row(i) for i in ins}
        context.append({'decoded_start_va':f'{start:08x}','decoded_end_exclusive_va':f'{end:08x}',
            'span_sha256':hashlib.sha256(raw(start,end)).hexdigest(),
            'selected_sites':{f'{a:08x}':mapping[a] for a in sites}})
    imports = {}
    descriptor = base+struct.unpack_from('<I',data,opt+104)[0]
    while True:
        oft,_,_,name,iat = struct.unpack('<IIIII',raw(descriptor,descriptor+20))
        if not any((oft,name,iat)):
            break
        slot = 0
        while True:
            target = struct.unpack('<I',raw(base+oft+slot*4,base+oft+slot*4+4))[0]
            if not target:
                break
            va = base+iat+slot*4
            if va in (0x967154,0x96715c):
                assert target < 0x80000000
                imports[f'{va:08x}'] = {'dll':string(base+name),'name':string(base+target+2)}
            slot += 1
        descriptor += 20
    assert imports == {'00967154':{'dll':'KERNEL32.dll','name':'HeapAlloc'},
                       '0096715c':{'dll':'KERNEL32.dll','name':'HeapFree'}}
    assert string(0xa8ccd0).endswith('\\training_manager.cpp')
    return {'schema_version':1,'specimen_sha256':SHA,
        'baseline_commit':'87ea0f39d5dcb62fe6969ad6570c3dca8b152673',
        'address_kind':'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method':'Capstone 5.0.7 static PE decode; optional whole-owned-body native comparison; no execution',
        'source_anchor':{'va':'00a8ccd0','basename':'training_manager.cpp','limit':'navigation evidence only'},
        'private_export_manifest_sha256':MANIFEST_SHA if native else None,
        'native_normalization':'jump aliases, numeric spelling, whitespace, redundant absolute EAX DWORD qualifier and implicit string operands; all other widths preserved',
        'owned_bodies':bodies,'selected_context_spans':context,'selected_imports':imports,
        'limitations':['Context spans are dependency alignment/evidence only, not fully reversed functions.',
            'No runtime lifecycle, RNG-state, allocation-failure or original-instruction behavior oracle.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--native-dir',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    result = extract(args.binary,args.native_dir)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('R13-C: pinned PE, five owned bodies and selected dependency/import sites verified')
