#!/usr/bin/env python3
"""R12-C static evidence from a read-only PE; requires capstone==5.0.7.

Retains selected instruction sites and hashes, never executable bytes or full
decompilation. Optional private Ghidra exports corroborate owned bodies/refs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
OWNED = [(0x727e20, 0x727ef3), (0x727f00, 0x727f9a)]
SELECTED = {
    0x727e20: [0x727e28,0x727e31,0x727e33,0x727e5c,0x727e8b,0x727e91,
               0x727e9d,0x727ea5,0x727eac,0x727eb2,0x727eb3,0x727eb4,
               0x727eba,0x727ebe,0x727ebf,0x727ec1,0x727ece,0x727ed1,
               0x727ed3,0x727ed6,0x727ed8,0x727edc,0x727ede,0x727edf,
               0x727ee2,0x727ee4,0x727ef2],
    0x727f00: [0x727f00,0x727f0a,0x727f0c,0x727f37,0x727f67,0x727f77,
               0x727f78,0x727f7a,0x727f7c,0x727f7e,0x727f83,0x727f88,
               0x727f89,0x727f99],
}
# Decode dependencies to known instruction boundaries but retain only these sites.
LEADS = {
    (0x727c30,0x727e1c): [0x727c36,0x727c3b,0x727c47,0x727c49,0x727c5d,
        0x727d70,0x727d76,0x727d7c,0x727d7e,0x727d7f,0x727d80,0x727d85,
        0x727d87,0x727d8f,0x727d93,0x727d98,0x727d9a,0x727d9c,0x727d9d,
        0x727d9e,0x727da3,0x727da6,0x727da8,0x727dac,0x727dae,0x727db8,
        0x727db9,0x727dba,0x727dbb,0x727dcb,0x727e09,0x727e0c,0x727e12],
    (0x8968f0,0x896a8e): [0x896902,0x896939,0x896942,0x896948,0x89694b,
        0x896951,0x89695c,0x896961,0x896964,0x89696a,0x896972,0x896978,
        0x89697b,0x89697e,0x896980,0x896985,0x89698d,0x896990,0x89699f,
        0x8969a4,0x8969a6,0x8969aa,0x8969ac,0x8969b1,0x8969c0,0x8969d9,
        0x8969dd,0x8969e5,0x8969ef,0x8969f2,0x8969fe,0x896a14,0x896a20],
    (0x897760,0x897871): [0x8977a7,0x8977b7,0x8977c2,0x8977c7,
        0x8977d0,0x8977d3,0x8977d9,0x8977dc,0x8977de,0x8977e1,0x8977e4,
        0x8977e8,0x8977ed,0x8977f2,0x8977fe],
    (0x6e1cf0,0x6e1fd7): [0x6e1cf9,0x6e1d20,0x6e1d27,0x6e1d38,
        0x6e1d3d,0x6e1dc8,0x6e1ef4,0x6e1fce,0x6e1fcf,0x6e1fd6],
    (0x7fe4a0,0x7fe5f7): [0x7fe4a2,0x7fe4ac,0x7fe4af,0x7fe4b6,
        0x7fe4c4,0x7fe4cb,0x7fe4e4,0x7fe4ed,0x7fe4f1,0x7fe4f5,
        0x7fe4f9,0x7fe4fa,0x7fe4fb,0x7fe4ff,0x7fe500,0x7fe501,0x7fe504,0x7fe547,0x7fe560,
        0x7fe580,0x7fe5c1,0x7fe5c9,0x7fe5d0,0x7fe5d8,0x7fe5e4,
        0x7fe5ed,0x7fe5f4],
    (0x7fe600,0x7feb1b): [0x7fe629,0x7fe62b,0x7fe62d,0x7fe633,
        0x7fe635,0x7fe63d,0x7fe667,0x7fe67c,0x7fe686,0x7fe68d,0x7fe695,0x7fe86b,
        0x7fe86d,0x7fe872,0x7fe88e,0x7fe895,0x7fe89c,0x7fe89e,
        0x7fe8a5,0x7fe8a8,0x7fe8af,0x7fe8b2,0x7fea56],
    (0x727fa0,0x727fa9): [0x727fa0,0x727fa2,0x727fa8],
    (0x727fb0,0x7280d5): [0x727fb8,0x727fca,0x727fcf,0x727ff6,
        0x728031,0x72803f,0x7280a0,0x7280a8,0x7280b8,0x7280bf,0x7280cb],
    (0x6b4668,0x6b4693): [0x6b4668,0x6b466e,0x6b466f,0x6b4675,
        0x6b467a,0x6b467b,0x6b4685,0x6b4690],
}


def norm(s):
    s = s.lower()
    for a,b in [('jz','je'),('jnz','jne')]:
        s = re.sub(r'\b'+a+r'\b',b,s)
    s = re.sub(r'\b0x[0-9a-f]+\b',lambda m:str(int(m[0],16)),s)
    s = re.sub(r'\s+','',s).replace('dwordptr','')
    return re.sub(r'\*1(?![0-9])','',s).replace('+0]',']')


def extract(binary, native):
    if capstone.__version__ != '5.0.7':
        raise ValueError('requires capstone==5.0.7')
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('specimen SHA-256 mismatch')
    pe = struct.unpack_from('<I',data,0x3c)[0]
    opt = pe+24
    assert data[:2] == b'MZ' and data[pe:pe+4] == b'PE\0\0'
    assert struct.unpack_from('<H',data,opt)[0] == 0x10b
    base = struct.unpack_from('<I',data,opt+28)[0]
    count = struct.unpack_from('<H',data,pe+6)[0]
    size = struct.unpack_from('<H',data,pe+20)[0]
    sections = [struct.unpack_from('<8sIIII',data,opt+size+40*i) for i in range(count)]

    def offset(va,n):
        for _,_,rva,rawsize,raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+n <= rawsize:
                return raw+delta
        raise ValueError(f'unbacked VA range {va:x}+{n:x}')

    def raw(start,end):
        off = offset(start,end-start)
        return data[off:off+end-start]

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail = True

    def decode(start,end):
        rows = list(md.disasm(raw(start,end),start))
        assert rows and rows[0].address == start
        assert rows[-1].address+rows[-1].size == end
        assert sum(i.size for i in rows) == end-start
        return rows

    def row(i):
        return (i.mnemonic+' '+i.op_str).strip()

    bodies = []
    for start,end in OWNED:
        ins = decode(start,end)
        mapping = {i.address:row(i) for i in ins}
        receipt = None
        if native:
            name = f'{start:08x}'
            listing = {int(l[:8],16):l[10:] for l in (native/(name+'.asm')).read_text().splitlines() if l}
            assert {a:norm(t) for a,t in mapping.items()} == {a:norm(t) for a,t in listing.items()}
            refs = (native/(name+'.refs')).read_text().splitlines()
            assert refs == (["00727d9e UNCONDITIONAL_CALL"] if start == 0x727e20 else ["006b4685 UNCONDITIONAL_CALL"])
            receipt = {'all_instructions_match':True,'incoming_references':refs,
                'export_sha256':{name+ext:hashlib.sha256((native/(name+ext)).read_bytes()).hexdigest()
                                 for ext in ('.asm','.c','.refs')},
                'normalization':'jump aliases, numeric spelling, whitespace, redundant DWORD PTR/scale1/+0'}
        bodies.append({'entry_va':f'{start:08x}','end_exclusive_va':f'{end:08x}',
            'file_offset':f'{offset(start,end-start):08x}','length':end-start,
            'body_sha256':hashlib.sha256(raw(start,end)).hexdigest(),
            'decoded_instruction_count':len(ins),
            'selected_sites':{f'{a:08x}':mapping[a] for a in SELECTED[start]},
            'all_direct_calls':[{'site':f'{i.address:08x}','target':i.op_str} for i in ins if i.mnemonic=='call'],
            'direct_nonstack_stores':[{'site':f'{i.address:08x}','instruction':row(i),'width_bytes':i.operands[0].size}
                for i in ins if i.mnemonic=='mov' and i.operands[0].type==capstone.x86.X86_OP_MEM
                and i.operands[0].mem.base not in (capstone.x86.X86_REG_ESP,capstone.x86.X86_REG_EBP)],
            'native_comparison':receipt})
    context = {}
    for (start,end),sites in LEADS.items():
        mapping = {i.address:row(i) for i in decode(start,end)}
        context.update({f'{a:08x}':mapping[a] for a in sites})
    # Static invariants: retain operand widths and branch direction, not only names.
    assert context['008969b1'] == 'mov dword ptr [ecx], 0xffffffff'
    assert context['008969fe'] == 'mov dword ptr [ecx + edi + 2], 0xffffffff'
    assert context['008977ed'] == 'mov dword ptr [ecx + edx + 0x52], eax'
    assert context['007fe5f4'] == 'ret 0x18'
    assert context['007fe8b2'] == 'mov dword ptr [edx + 8], ecx'
    assert len(bodies[0]['all_direct_calls']) == 6
    assert len(bodies[1]['all_direct_calls']) == 5
    # Original embedded path is checked privately; only basename is retained.
    assert raw(0xa161d4,0xa16250).split(b'\0')[0].endswith(b'\\match_screens.cpp')
    return {'schema_version':1,'specimen_sha256':SHA,
        'baseline':'a5972e1659afa4b2937490cdc57ebd8f4a5887d3','address_kind':'PE virtual addresses unless file_offset is explicit',
        'method':'Capstone 5.0.7 static PE decode; no execution, no native writes',
        'source_anchor':{'va':'00a161d4','basename':'match_screens.cpp','semantic_limit':'navigation evidence only'},
        'owned_bodies':bodies,'selected_dependency_sites':context,
        'limitations':['Dependency bodies decoded for instruction alignment only; selected sites do not establish complete dependency contracts.',
            'No dynamic observations, numerical oracle, transitive RNG audit, callback lifetime or allocation ownership proof.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--native-dir',type=Path)
    args = parser.parse_args()
    result = extract(args.binary,args.native_dir)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('R12-C: pinned PE decoded; selected sites and optional native agreement passed')
