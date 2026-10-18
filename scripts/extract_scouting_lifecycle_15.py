#!/usr/bin/env python3
"""R15-C compact static PE evidence; Capstone 5.0.7; never writes native state."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = '65503dc3cf33eff2a9a40c1cdc456f5798bc8e04d1d9bbad6132c06b9677ca58'
PREFLIGHT_SHA = 'c20393d151da0afff24f0ff7f806f91857d90f454cbff5a52d7bc0463517d1f1'
OWNED = [(0x7f6760,818),(0x7f6aa0,74),(0x8041c0,251),(0x804450,80)]
SELECTED = {
    0x7f6760:[0x7f677d,0x7f6785,0x7f678b,0x7f6790,0x7f6797,0x7f679d,
        0x7f67a3,0x7f67ae,0x7f67b3,0x7f67cc,0x7f67ce,0x7f67e8,0x7f680d,
        0x7f6817,0x7f6821,0x7f6829,0x7f682c,0x7f682f,0x7f687c,
        0x7f6881,0x7f6884,0x7f6889,0x7f688b,0x7f688d,0x7f6894,0x7f6898,
        0x7f689d,0x7f689e,0x7f68a0,0x7f68a2,0x7f68a7,0x7f68ac,0x7f68b3,
        0x7f68b9,0x7f68be,0x7f68c5,0x7f68c8,0x7f68cb,0x7f68ce,0x7f68e3,
        0x7f68e5,0x7f68ea,0x7f68ef,0x7f68f2,0x7f68f7,0x7f68fd,0x7f6903,
        0x7f690e,0x7f691d,0x7f6920,0x7f694f,0x7f697b,0x7f698b,
        0x7f6992,0x7f69a1,0x7f69a9,0x7f69b5,0x7f69bd,0x7f69c0,0x7f69c3,
        0x7f69c6,0x7f69cb,0x7f69d6,0x7f69d9,0x7f69db,0x7f69dd,0x7f69de,
        0x7f69e5,0x7f69e7,0x7f69ea,0x7f69ed,0x7f69f4,0x7f69f9,0x7f69ff,
        0x7f6a00,0x7f6a05,0x7f6a09,0x7f6a0d,0x7f6a12,0x7f6a16,0x7f6a1b,
        0x7f6a1f,0x7f6a23,0x7f6a28,0x7f6a2b,0x7f6a2d,0x7f6a2e,0x7f6a2f,
        0x7f6a37,0x7f6a39,0x7f6a40,0x7f6a4f,0x7f6a52,0x7f6a55,0x7f6a6b,
        0x7f6a7d,0x7f6a8f],
    0x7f6aa0:[0x7f6aa1,0x7f6aa3,0x7f6aa7,0x7f6aa9,0x7f6aad,0x7f6ab0,
        0x7f6ab5,0x7f6ab6,0x7f6abb,0x7f6abc,0x7f6ac2,0x7f6aca,0x7f6ad1,
        0x7f6ad6,0x7f6ad8,0x7f6ad9,0x7f6ae1,0x7f6ae9],
    0x8041c0:[0x8041da,0x8041dc,0x8041e1,0x8041e6,0x8041e8,0x8041eb,
        0x8041f5,0x804204,0x804206,0x80420c,0x80421a,0x80421f,0x80422a,
        0x80422f,0x804238,0x80423a,0x80423c,0x80423e,0x804240,0x804246,
        0x804248,0x80424f,0x804251,0x804255,0x80425b,0x80425f,0x804261,
        0x804262,0x804268,0x80426d,0x80426e,0x804270,0x804275,0x80427e,
        0x804284,0x804287,0x80428e,0x804296,0x80429c,0x8042a2,0x8042a8,0x8042b8],
    0x804450:[0x804453,0x804455,0x804457,0x80445d,0x80445f,0x804460,
        0x804467,0x804468,0x80446c,0x804470,0x804471,0x804473,0x804474,
        0x80447a,0x80447f,0x804481,0x804488,0x80448e,0x804495,0x804498,0x80449f],
}
# Selected boundary evidence only; these helpers are not new full-body contracts.
CONTEXT = {
    (0x7b7690,0x7b7835):[0x7b76ad,0x7b76b3,0x7b76be,0x7b76cc,0x7b76dc,
        0x7b76e2,0x7b76f0,0x7b76f7,0x7b76fc,0x7b76fe,0x7b7700,0x7b7702,
        0x7b7717,0x7b77b8,0x7b77bf,0x7b77c1,0x7b77d0,0x7b7804,0x7b780b,0x7b7832],
    (0x68d020,0x68d031):[0x68d020,0x68d022,0x68d024,0x68d027,0x68d02a,0x68d02d,0x68d030],
    (0x944c94,0x944c9f):[0x944c94,0x944c98,0x944c9e],
    (0x944cf1,0x944cff):[0x944cf1,0x944cf3,0x944cf7,0x944cfe],
    (0x9463af,0x946419):[0x9463e0,0x9463e5,0x9463e8,0x9463ea,0x9463ed,0x946416],
    (0x9462bb,0x946323):[0x9462e2,0x9462e7,0x9462eb,0x9462f2,0x9462f7,0x9462fa,0x9462fd,0x946320],
    (0x80857c,0x8085c1):[0x80857c,0x808581,0x80859d,0x80859e,0x8085a0,0x8085ab,0x8085b1,0x8085b3,0x8085bc],
    (0x8131d3,0x81320b):[0x8131d3,0x8131d5,0x8131da,0x8131dc,0x8131e1,0x8131e2,0x8131fa,0x813200,0x813202,0x813204],
}


def norm(text):
    text = text.lower()
    text = re.sub(r'\bjz\b','je',text)
    text = re.sub(r'\bjnz\b','jne',text)
    text = re.sub(r'\bmov eax,\[','mov eax,dword ptr [',text)
    text = text.replace('mov eax,fs:[','mov eax,dword ptr fs:[')
    text = text.replace('stosd.rep es:edi','rep stosd dword ptr es:[edi],eax')
    text = re.sub(r'\b0x[0-9a-f]+\b',lambda m:str(int(m[0],16)),text)
    return re.sub(r'\s+','',text).replace('+0]',']').replace('*1', '').replace('+-','-')


def extract(binary, native, preflight):
    assert capstone.__version__ == '5.0.7'
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

    def offset(va,size=1):
        for _,_,rva,rawsize,raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= rawsize:
                return raw+delta
        raise ValueError(f'unbacked VA {va:x}')

    def raw(start,end):
        off = offset(start,end-start)
        return data[off:off+end-start]

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    def decode(start,end):
        rows = list(md.disasm(raw(start,end),start))
        assert rows and rows[0].address == start and rows[-1].address+rows[-1].size == end
        assert sum(i.size for i in rows) == end-start
        return rows

    def row(ins):
        return (ins.mnemonic+' '+ins.op_str).strip()

    path = native/'EXPORT-MANIFEST.json'
    assert hashlib.sha256(path.read_bytes()).hexdigest() == MANIFEST_SHA
    manifest = json.loads(path.read_text())
    assert manifest['specimen_sha256'] == SHA
    for entry in manifest['files']:
        content = (native/entry['name']).read_bytes()
        assert len(content) == entry['bytes']
        assert hashlib.sha256(content).hexdigest() == entry['sha256']
    assert hashlib.sha256(preflight.read_bytes()).hexdigest() == PREFLIGHT_SHA
    receipt = json.loads(preflight.read_text())
    assert receipt['sha256'] == SHA
    old_names = {r['address']:r['function_name'] for r in receipt['sites'] if r['instruction_exists']}
    assert all(old_names[f'{a:08x}'] == f'FUN_{a:08x}' for a,_ in OWNED)
    bodies = []
    for start,size in OWNED:
        ins = decode(start,start+size)
        mapping = {i.address:row(i) for i in ins}
        name = f'{start:08x}'
        listing = {int(l[:8],16):l[10:] for l in (native/(name+'.asm')).read_text().splitlines() if l}
        left = {a:norm(t) for a,t in mapping.items()}
        right = {a:norm(t) for a,t in listing.items()}
        assert left == right, [(hex(a),left.get(a),right.get(a)) for a in left.keys()|right.keys() if left.get(a)!=right.get(a)]
        incoming = [int(l.split()[0],16) for l in (native/(name+'.refs')).read_text().splitlines()]
        for a in incoming:
            call = decode(a,a+5)
            assert len(call)==1 and call[0].mnemonic=='call' and int(call[0].op_str,16)==start
        bodies.append({'entry_va':name,'end_exclusive_va':f'{start+size:08x}',
            'file_offset':f'{offset(start,size):08x}','length_bytes':size,
            'body_sha256':hashlib.sha256(raw(start,start+size)).hexdigest(),
            'instruction_count':len(ins),'selected_sites':{f'{a:08x}':mapping[a] for a in SELECTED[start]},
            'all_calls':[{'site':f'{i.address:08x}','target':i.op_str} for i in ins if i.mnemonic=='call'],
            'all_branches':[{'site':f'{i.address:08x}','instruction':row(i)} for i in ins if i.mnemonic.startswith('j')],
            'native_comparison':{'all_instructions_match':True,
                'incoming_direct_calls_verified':[f'{a:08x}' for a in incoming],
                'export_sha256':{name+ext:hashlib.sha256((native/(name+ext)).read_bytes()).hexdigest() for ext in ('.asm','.c','.refs')}}})
    context = []
    for (start,end),sites in CONTEXT.items():
        mapping = {i.address:row(i) for i in decode(start,end)}
        context.append({'decoded_start_va':f'{start:08x}','decoded_end_exclusive_va':f'{end:08x}',
            'span_sha256':hashlib.sha256(raw(start,end)).hexdigest(),
            'selected_sites':{f'{a:08x}':mapping[a] for a in sites}})
    # Recover the two selected import names directly from the PE import directory.
    imports = {}
    import_rva = struct.unpack_from('<I',data,opt+104)[0]
    cursor = offset(base+import_rva,20)
    while any(data[cursor:cursor+20]):
        lookup,_,_,dll,iat = struct.unpack_from('<IIIII',data,cursor)
        index = 0
        while True:
            thunk = struct.unpack_from('<I',data,offset(base+(lookup or iat)+4*index,4))[0]
            if not thunk:
                break
            va = base+iat+4*index
            if va in (0x9670f8,0x967100):
                assert not thunk & 0x80000000
                off = offset(base+thunk+2)
                imports[f'{va:08x}'] = data[off:data.index(b'\0',off)].decode('ascii')
            index += 1
        cursor += 20
    assert imports == {'009670f8':'GetLogicalDriveStringsA','00967100':'GetDriveTypeA'}
    return {'schema_version':1,'specimen_sha256':SHA,
        'baseline_commit':'a4fa4bc7745ad3fbc67759325c45a9058ceaecc0','native_checkpoint':'2026-10-18-investigation-14',
        'address_kind':'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method':'Capstone 5.0.7 whole-owned-body static decode, every instruction compared to read-only native export; no execution',
        'private_export_manifest_sha256':MANIFEST_SHA,'private_annotation_preflight_sha256':PREFLIGHT_SHA,
        'verified_old_names':{f'{a:08x}':old_names[f'{a:08x}'] for a,_ in OWNED},
        'native_normalization':'jump aliases, numeric spelling, whitespace, EAX absolute/FS DWORD qualifier, scale-one and plus-negative spelling, REP STOSD rendering; other operand widths preserved',
        'selected_imports':imports,'owned_bodies':bodies,'selected_context_spans':context,
        'limitations':['Selected helper sites establish boundaries only; helper contracts are not complete.',
            'No execution oracle, complete scouting lifecycle, persistence, exclusive ownership or workflow equivalence.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--native-dir',required=True,type=Path)
    parser.add_argument('--preflight',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    args.output.write_bytes((json.dumps(extract(args.binary,args.native_dir,args.preflight),indent=2)+'\n').encode('utf-8'))
    print('R15-C: four complete owned instruction ranges, incoming calls, selected helper and import boundaries verified')
