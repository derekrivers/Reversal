#!/usr/bin/env python3
"""Read-only original PE evidence; requires capstone==5.0.7.

python contract-dependencies-13-extract.py SPECIMEN OUTPUT --native-dir EXPORTS
No original instruction bytes, bulk listing, game table or memory dump is emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "fa2728212d3189f2a0ec9f4db14b2355b0da8457bc9bff091d5c2b442b38a489"
BODIES = [(0x4d0c60,2450),(0x4cf5f0,209)]
# Selected operand/branch sites only; complete listing stays in the private exports.
SELECTED = """
4d0c60 4d0c63 4d0c6a 4d0c7f 4d0c81 4d0c94 4d0c99 4d0c9f
4d0cab 4d0caf 4d0cb6 4d0cc9 4d0cd0 4d0cd1 4d0cdb 4d0ce4
4d0cea 4d0d00 4d0d0a 4d0d22 4d0d3a 4d0d52 4d0d68 4d0d6f
4d0d75 4d0d88 4d0d8d 4d0d9d 4d0daa 4d0db9 4d0dc9 4d0dd3
4d0dda 4d0dde 4d0df8 4d0dfc 4d0e0f 4d0e19 4d0e2e 4d0e93
4d0e95 4d0ea6 4d0ec2 4d0ee3 4d0efc 4d0f15 4d0f20 4d0f28
4d0f31 4d0f43 4d0f46 4d0f4c 4d0f50 4d0f5b 4d0f69 4d0f6f
4d0f71 4d0f76 4d0f78 4d0f80 4d0f87 4d0f96 4d0fa2 4d0fb7
4d0fba 4d0fc3 4d0fcf 4d0fd3 4d0feb 4d0ff6 4d0fff 4d1001
4d1005 4d1016 4d1055 4d1067 4d1071 4d1079 4d106a 4d108b
4d1092 4d1099 4d10b6 4d10bb 4d10c3 4d10cf 4d10db 4d10df
4d10e7 4d10eb 4d10f0 4d1113 4d111e 4d1125 4d1159 4d1175
4d1182 4d11ad 4d11f8 4d1208 4d1225 4d122f 4d1261 4d1278
4d129f 4d12ce 4d12d8 4d12dd 4d12ee 4d12f5 4d130c 4d1331
4d1351 4d135d 4d1366 4d136c 4d137a 4d138d 4d139c 4d13a2
4d13b4 4d13b8 4d13c1 4d13cb 4d13d9 4d13e0 4d13e6 4d13ec
4d13f3 4d13fc 4d140a 4d141d 4d1428 4d1432 4d144f 4d1464
4d1476 4d1495 4d149c 4d14ad 4d14b8 4d14cb 4d14d3 4d1523
4d152a 4d1541 4d1555 4d1571 4d1585 4d159a 4d15a5 4d15a7
4d15b5 4d15bd 4d15c8 4d15cb 4d15cf 4d15d5 4d15d7 4d15d8
4d15e4 4d15e9 4d15ef
4cf5f0 4cf600 4cf614 4cf616 4cf62b 4cf62f 4cf635 4cf63d
4cf63f 4cf641 4cf647 4cf651 4cf654 4cf659 4cf65b 4cf65d
4cf661 4cf663 4cf664 4cf671 4cf677 4cf679 4cf67b 4cf681
4cf68e 4cf694 4cf696 4cf698 4cf6a3 4cf6a6 4cf6aa 4cf6b5 4cf6be
"""
CONTEXT = [(0x4c766b,0x4c766f),(0x4c767c,0x4c768e),
           (0x4d15ef,0x4d1600),(0x4cf6be,0x4cf6d0)]


def normalize(text):
    text = text.lower().replace("double ptr","qword ptr").replace("float ptr","dword ptr")
    for old,new in [("jz","je"),("jnz","jne"),("jc","jb")]:
        text = re.sub(r"\b"+old+r"\b",new,text)
    text = re.sub(r"st\(([0-7])\)",r"st\1",text)
    text = re.sub(r"\b0x[0-9a-f]+\b",lambda m:str((int(m[0],16)+2**31)%2**32-2**31),text)
    text = re.sub(r"\s+","",text).replace("dwordptr","")
    text = re.sub(r"\*1(?![0-9])","",text).replace("+0]","]").replace("+-","-")
    if text in ["fxch","fmulp","faddp","fdivp","fcomp"]:
        text += "st1"
    if text == "fsubst0,st1":
        text = "fsubst1"
    return text


def extract(specimen,native_dir):
    assert capstone.__version__ == "5.0.7"
    data = specimen.read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED, "specimen mismatch"
    pe = struct.unpack_from("<I",data,0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    opt = pe+24
    assert struct.unpack_from("<H",data,opt)[0] == 0x10b
    base = struct.unpack_from("<I",data,opt+28)[0]
    count = struct.unpack_from("<H",data,pe+6)[0]
    opt_size = struct.unpack_from("<H",data,pe+20)[0]
    sections = [struct.unpack_from("<8sIIII",data,opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _,_,rva,size,raw in sections:
            delta = va-base-rva
            if 0 <= delta < size:
                return raw+delta
        raise ValueError(f"VA{va:08x} not file-backed")

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail = True
    manifest_path = native_dir/"EXPORT-MANIFEST.json"
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == MANIFEST
    manifest = json.loads(manifest_path.read_text())
    assert manifest["specimen_sha256"] == PINNED
    expected = {f["name"]:f for f in manifest["files"]}
    functions,insns,constants = [],{},{}
    for start,size in BODIES:
        raw = data[offset(start):offset(start)+size]
        rows = list(md.disasm(raw,start))
        assert sum(i.size for i in rows) == size and rows[-1].mnemonic == "ret"
        by_address = {i.address:i for i in rows}
        native = {int(l[:8],16):l[10:] for l in (native_dir/f"{start:08x}.asm").read_text().splitlines()}
        assert {a:normalize(t) for a,t in native.items()} == {
            i.address:normalize(i.mnemonic+" "+i.op_str) for i in rows}, "native instruction mismatch"
        exports = []
        for suffix in ["asm","c","refs"]:
            p = native_dir/f"{start:08x}.{suffix}"
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            assert digest == expected[p.name]["sha256"] and p.stat().st_size == expected[p.name]["bytes"]
            exports.append({"name":p.name,"bytes":p.stat().st_size,"sha256":digest})
        refs = [l.split()[0] for l in (native_dir/f"{start:08x}.refs").read_text().splitlines() if l]
        for site in refs:
            va = int(site,16)
            caller = next(md.disasm(data[offset(va):offset(va)+5],va))
            assert caller.mnemonic == "call" and caller.size == 5 and caller.operands[0].imm == start
        jumps = [i for i in rows if i.group(capstone.CS_GRP_JUMP)]
        assert all(i.operands[0].type == capstone.x86.X86_OP_IMM and
                   i.operands[0].imm in by_address for i in jumps), "out-of-body/noninstruction branch"
        colors = {}
        def visit(va):
            assert colors.get(va) != 1, "owned CFG cycle"
            if colors.get(va) == 2:
                return
            colors[va] = 1
            i = by_address[va]
            successors = [] if i.mnemonic == "ret" else [va+i.size]
            if i.group(capstone.CS_GRP_JUMP):
                successors = [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else successors)
            for successor in successors:
                visit(successor)
            colors[va] = 2
        visit(start)
        assert len(colors) == len(rows), "unreachable instruction in supplied body"
        stores,frame_reads = [],set()
        for i in rows:
            insns[i.address] = (i.mnemonic+" "+i.op_str).strip()
            for op in i.operands:
                if op.type != capstone.x86.X86_OP_MEM:
                    continue
                m = op.mem
                if m.base == capstone.x86.X86_REG_EBP and op.access & capstone.CS_AC_READ:
                    frame_reads.add(m.disp)
                if op.access & capstone.CS_AC_WRITE and m.base not in [capstone.x86.X86_REG_ESP,capstone.x86.X86_REG_EBP]:
                    stores.append({"site":f"{i.address:08x}","width_bytes":op.size,"instruction":insns[i.address]})
                if i.mnemonic.startswith("f") and m.base == 0 and m.index == 0 and 0x960000 <= m.disp < 0x980000 and op.size in [4,8]:
                    fmt = "f" if op.size == 4 else "d"
                    constants[f"{m.disp:08x}"] = {"width_bytes":op.size,"value":struct.unpack_from("<"+fmt,data,offset(m.disp))[0]}
        functions.append({"entry_va":f"{start:08x}","last_body_byte_va":f"{start+size-1:08x}",
            "file_offset":f"{offset(start):08x}","span_bytes":size,"span_sha256":hashlib.sha256(raw).hexdigest(),
            "instruction_count":len(rows),"all_instructions_match_native":True,"all_branch_targets_in_body":True,
            "owned_cfg_acyclic":True,"all_instructions_statically_reachable":True,"incoming_reference_targets_verified":True,
            "calls":[{"site":f"{i.address:08x}","target":i.op_str} for i in rows if i.mnemonic == "call"],
            "returns":[{"site":f"{i.address:08x}","instruction":insns[i.address]} for i in rows if i.mnemonic == "ret"],
            "explicit_nonstack_memory_writes":stores,"ebp_based_read_displacements":sorted(frame_reads),
            "incoming_direct_call_count":len(refs),"incoming_direct_call_sites":refs,"exports":exports})
    assert [f["instruction_count"] for f in functions] == [714,91]
    assert functions[0]["explicit_nonstack_memory_writes"] == [{"site":"004d0caf","width_bytes":4,"instruction":"mov dword ptr [0xae1080], eax"}]
    assert functions[1]["explicit_nonstack_memory_writes"] == []
    assert functions[0]["ebp_based_read_displacements"] == [8,12,16,20]
    first_call_rows = [i for i in md.disasm(data[offset(0x4d0c60):offset(0x4d0cd6)],0x4d0c60)]
    assert all(capstone.x86.X86_REG_ECX not in i.regs_access()[1] for i in first_call_rows)
    context = {}
    for start,last in CONTEXT:
        rows = [i for i in md.disasm(data[offset(start):offset(last)+16],start) if i.address <= last]
        assert rows[-1].address == last
        context.update({f"{i.address:08x}":(i.mnemonic+" "+i.op_str).strip() for i in rows})
    selected = {f"{a:08x}":insns[a] for a in sorted(int(a,16) for a in SELECTED.split())}
    return {"sha256":PINNED,"baseline_commit":"87ea0f39d5dcb62fe6969ad6570c3dca8b152673",
        "method":"PE32 Capstone5.0.7, complete owned decode/native comparison; static only",
        "address_space":"virtual addresses except explicit file_offset; field offsets hexadecimal bytes",
        "native_export_manifest_sha256":MANIFEST,"functions":functions,"selected_instructions":selected,
        "caller_and_boundary_sites":context,"referenced_floating_constants":dict(sorted(constants.items())),
        "normalization":"x87 register/default operands and float/double width spelling; redundant DWORD PTR; jump aliases; signed32 numeric spelling; whitespace; scale1 and +0",
        "limits":"No execution/oracle, x87 environment measurement, transitive helper effects, dynamic caller completeness or native mutation. Original table009a7f30 is not emitted."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--native-dir",type=Path,required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.native_dir),indent=2)+"\n",encoding="utf-8")
