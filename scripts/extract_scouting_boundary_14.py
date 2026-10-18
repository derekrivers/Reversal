#!/usr/bin/env python3
"""R14-C compact static evidence. Capstone 5.0.7; no execution or native writes."""

# Integrity assertions must remain active before reading or writing evidence.
if not __debug__:
    raise SystemExit("Integrity checks require assertions; rerun without Python optimization (-O/-OO).")
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST_SHA = '233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86'
PREFLIGHT_SHA = '728f0dbb5ccd7860c03a35203f30b7bb377048879c2b95601b1744fd78e7fc3d'
OWNED = [(0x7f6af0,240),(0x7f6be0,229),(0x7f6cd0,338),(0x7f6e30,228),(0x7f6f20,240)]
SELECTED = {
    0x7f6af0:[0x7f6af0,0x7f6afe,0x7f6b05,0x7f6b08,0x7f6b0b,0x7f6b13,
        0x7f6b3c,0x7f6b44,0x7f6b46,0x7f6b4c,0x7f6b4e,0x7f6b50,0x7f6b52,0x7f6b54,
        0x7f6b56,0x7f6b59,0x7f6b60,0x7f6b64,0x7f6b6f,0x7f6b9b,0x7f6bcb,0x7f6bd5],
    0x7f6be0:[0x7f6be0,0x7f6bee,0x7f6bfb,0x7f6c2c,0x7f6c35,0x7f6c37,
        0x7f6c3d,0x7f6c3f,0x7f6c41,0x7f6c43,0x7f6c45,0x7f6c47,0x7f6c4a,
        0x7f6c54,0x7f6c80,0x7f6cb0,0x7f6cba],
    0x7f6cd0:[0x7f6cd0,0x7f6cda,0x7f6cdc,0x7f6ce2,0x7f6ce5,0x7f6ceb,0x7f6cf6,
        0x7f6d03,0x7f6d34,0x7f6d3f,0x7f6d42,0x7f6d48,0x7f6d4b,0x7f6d4e,
        0x7f6d51,0x7f6d54,0x7f6d57,0x7f6d59,0x7f6d5b,0x7f6d5e,0x7f6d5f,
        0x7f6d61,0x7f6d63,0x7f6d6a,0x7f6d6c,0x7f6d6f,0x7f6d72,0x7f6d74,
        0x7f6d77,0x7f6d7f,0x7f6dab,0x7f6ddd,0x7f6e0d,0x7f6e17],
    0x7f6e30:[0x7f6e30,0x7f6e3e,0x7f6e4b,0x7f6e7c,0x7f6e85,0x7f6e87,
        0x7f6e8d,0x7f6e8f,0x7f6e92,0x7f6e94,0x7f6e97,0x7f6e99,0x7f6ea3,
        0x7f6ecf,0x7f6eff,0x7f6f09,0x7f6f11],
    0x7f6f20:[0x7f6f20,0x7f6f2e,0x7f6f3b,0x7f6f6c,0x7f6f75,0x7f6f77,
        0x7f6f7d,0x7f6f7f,0x7f6f82,0x7f6f84,0x7f6f87,0x7f6f89,0x7f6f90,
        0x7f6f94,0x7f6f9f,0x7f6fcb,0x7f6ffb,0x7f7005],
}
# These are selected dependency sites, not new full-body research assignments.
CONTEXT = {
    (0x7f6760,0x7f6a92):[0x7f677d,0x7f6881,0x7f6884,0x7f6889,0x7f688b,
        0x7f68ac,0x7f68b3,0x7f68b9,0x7f68be,0x7f68ce,0x7f68ef,0x7f68f2,
        0x7f68f7,0x7f68fd,0x7f6903,0x7f691d,0x7f6992,0x7f69a1,0x7f6a4f,0x7f6a55,0x7f6a6b],
    (0x7f6aa0,0x7f6aea):[0x7f6aa3,0x7f6aa9,0x7f6ab6,0x7f6abc,0x7f6ac2,0x7f6aca],
    (0x8041c0,0x8042bb):[0x804240,0x804246,0x804248,0x80424f,0x80425f,0x804262,0x804268,0x80426d,0x804270],
    (0x804450,0x8044a0):[0x804455,0x804457,0x80445d,0x80445f,0x804460,0x804471,0x80447a,0x80447f,0x804481],
    (0x808540,0x808690):[0x80857c,0x80859e,0x8085a0,0x8085ab,0x8085b1,0x8085b3,0x8085bc],
    (0x8131c0,0x81320b):[0x8131d3,0x8131d5,0x8131da,0x8131dc,0x8131e1,0x8131e2,0x8131fa,0x813200,0x813202,0x813204],
}


def norm(text):
    text = text.lower()
    text = re.sub(r'\bjz\b','je',text)
    text = re.sub(r'\bjnz\b','jne',text)
    text = re.sub(r'\bmov eax,\[','mov eax,dword ptr [',text)
    text = re.sub(r'\b0x[0-9a-f]+\b',lambda m:str(int(m[0],16)),text)
    return re.sub(r'\s+','',text).replace('+0]',']').replace('*1', '')


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

    if native:
        path = native/'EXPORT-MANIFEST.json'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == MANIFEST_SHA
        manifest = json.loads(path.read_text())
        assert manifest['specimen_sha256'] == SHA
        for entry in manifest['files']:
            content = (native/entry['name']).read_bytes()
            assert len(content) == entry['bytes']
            assert hashlib.sha256(content).hexdigest() == entry['sha256']
    old_names = None
    if preflight:
        assert hashlib.sha256(preflight.read_bytes()).hexdigest() == PREFLIGHT_SHA
        receipt = json.loads(preflight.read_text())
        assert receipt['sha256'] == SHA
        old_names = {r['address']:r['function_name'] for r in receipt['sites'] if r['instruction_exists']}
        assert all(old_names[f'{a:08x}'] == f'FUN_{a:08x}' for a,_ in OWNED)
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
            incoming = [int(l.split()[0],16) for l in (native/(name+'.refs')).read_text().splitlines()]
            # Verify every native incoming ref as a direct call in original PE.
            for a in incoming:
                call = list(md.disasm(raw(a,a+5),a))
                assert len(call)==1 and call[0].mnemonic=='call' and int(call[0].op_str,16)==start
            receipt = {'all_instructions_match':True,'incoming_direct_calls_verified':[f'{a:08x}' for a in incoming],
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
    off = offset(0xa7b094)
    assert data[off:data.index(b'\0',off)].decode('ascii').endswith('\\scout_manager.cpp')
    return {'schema_version':1,'specimen_sha256':SHA,'baseline_commit':'3d81fa3c056c7d28c3c2a6d99e93d96464f43834',
        'address_kind':'PE virtual addresses unless file_offset is explicit; field offsets in bytes',
        'method':'Capstone 5.0.7 static PE decode; optional all-owned-instruction and incoming-call native comparison; no execution',
        'source_anchor':{'va':'00a7b094','basename':'scout_manager.cpp','limit':'navigation only'},
        'private_export_manifest_sha256':MANIFEST_SHA if native else None,
        'private_annotation_preflight_sha256':PREFLIGHT_SHA if preflight else None,
        'verified_old_names':{f'{a:08x}':old_names[f'{a:08x}'] for a,_ in OWNED} if old_names else None,
        'native_normalization':'jump aliases, numeric spelling, whitespace, absolute EAX DWORD qualifier and scale-one spelling; other operand widths preserved',
        'owned_bodies':bodies,'selected_context_spans':context,
        'limitations':['Context spans are selected dependencies, not fully reversed functions.',
            'No runtime lifecycle, behavioral oracle, persistence or full scouting workflow claim.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--native-dir',type=Path)
    parser.add_argument('--preflight',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    # Explicit UTF-8/LF bytes make the retained result identical on Windows/Linux.
    args.output.write_bytes((json.dumps(extract(args.binary,args.native_dir,args.preflight),indent=2)+'\n').encode('utf-8'))
    print('R14-C: five owned bodies, selected context and optional native/preflight evidence verified')
