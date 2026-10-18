#!/usr/bin/env python3
"""Verify every owned instruction; extract compact field-transfer facts.

Requires capstone==5.0.7. Usage: SPECIMEN EXPORT_DIR OUTPUT
No original bytes, full instruction listing or decompiled source is emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "65503dc3cf33eff2a9a40c1cdc456f5798bc8e04d1d9bbad6132c06b9677ca58"
ROWS = [(0x54dc90,2365,0x245,"edi",0), (0x54e9a0,1583,0x44,"esi",0),
        (0x54f150,2652,0x46,"esi",0), (0x54ffd0,510,0x6b,"esi",0x38)]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def normalize(text):
    text = text.lower()
    for old,new in [("jz","je"),("jnz","jne"),("jc","jb")]:
        text = re.sub(r"\b"+old+r"\b",new,text)
    text = re.sub(r"\b0x[0-9a-f]+\b",lambda m:str(int(m[0],16)),text)
    text = re.sub(r"\s+","",text)
    return text.replace("+0]","]").replace("+-","-")


def expected(entry):
    # Independently transcribed field groups: (destination offset, width, repeat).
    if entry == 0x54dc90:
        pairs = [(0,4),(4,51),(0x38,26),(0x53,4),(0x57,4),(0x5b,4),
                 (0x5f,1),(0x60,4),(0x64,1),(0x65,4),(0x69,4),(0x6d,1),
                 (0x6e,4),(0x72,1),(0x73,4),(0x77,4),(0x7b,4),(0x7f,1),
                 (None,1),(0x82,1)] + [(x,4) for x in range(0x83,0xc0,4)]
        groups = [(o,w,1) for o,w in pairs]
        return groups + [(0xc3,4,3),(0xcf,4,1),(0xd3,4,1),(0xd7,4,50),
                         (0x19f,4,5),(0x1b3,4,7),(0x1cf,4,3),(0x1db,4,1),
                         (0x1df,1,1),(0x1e0,4,20),(0x230,4,4),(0x240,4,1)]
    if entry == 0x54e9a0:
        pairs = [(0,4),(4,2),(6,2)] + [(None,1)]*3
        pairs += [(x,1) for x in range(0xe,0x23)]
        pairs += [(x,4) for x in range(0x23,0x40,4)] + [(0x43,1)]
    elif entry == 0x54f150:
        pairs = [(0,4),(4,1),(5,2),(7,2)] + [(None,1)]*3
        pairs += [(x,1) for x in range(0xf,0x46)]
    else:
        pairs = [(0,4),(4,51),(0x38,26),(0x53,4),(0x57,1),(0x58,1),
                 (0x59,4),(0x5d,4),(0x61,4),(0x65,4),(None,1)]
    return [(o,w,1) for o,w in pairs]


def extract(specimen,exports):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    assert digest(data) == PINNED, "specimen mismatch"
    manifest_raw = (exports/"EXPORT-MANIFEST.json").read_bytes()
    assert digest(manifest_raw) == MANIFEST, "native manifest mismatch"
    manifest = json.loads(manifest_raw)
    assert manifest["specimen_sha256"] == PINNED
    files = {r["name"]:r for r in manifest["files"]}
    pe = struct.unpack_from("<I",data,0x3c)[0]
    opt = pe+24
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    assert struct.unpack_from("<H",data,opt)[0] == 0x10b
    base = struct.unpack_from("<I",data,opt+28)[0]
    count = struct.unpack_from("<H",data,pe+6)[0]
    opt_size = struct.unpack_from("<H",data,pe+20)[0]
    sections = [struct.unpack_from("<8sIIII",data,opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _,_,rva,raw_size,raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size:
                return raw_offset+delta
        raise ValueError(f"VA not file backed: {va:08x}")

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail = True
    result = []
    for start,size,stride,record_reg,bias in ROWS:
        entry = f"{start:08x}"
        raw = data[offset(start):offset(start)+size]
        ins = list(md.disasm(raw,start))
        assert sum(i.size for i in ins) == size
        native_hashes = {}
        for suffix in ["asm","c","refs"]:
            name = entry+"."+suffix
            exported = (exports/name).read_bytes()
            assert digest(exported) == files[name]["sha256"]
            assert len(exported) == files[name]["bytes"]
            native_hashes[suffix] = digest(exported)
        native = {}
        for line in (exports/(entry+".asm")).read_text().splitlines():
            address,text = line.split(None,1)
            native[int(address,16)] = normalize(text)
        own = {i.address:normalize(i.mnemonic+" "+i.op_str) for i in ins}
        assert own == native, f"native instruction mismatch {entry}"
        calls = [(n,i) for n,i in enumerate(ins) if i.mnemonic == "call"]
        assert all(i.operands[0].type == X86_OP_IMM and
                   i.operands[0].imm in [0x932c30,0x945bfe] for _,i in calls)
        assert len(calls)%2 == 0
        # Follow actual control-flow predecessors, so the zero-mode alternative
        # cannot accidentally inherit pushes from the adjacent nonzero call.
        predecessors = {i.address:[] for i in ins}
        for index,i in enumerate(ins):
            successors = []
            if i.mnemonic.startswith("j"):
                successors.append(i.operands[0].imm)
            if i.mnemonic not in ["jmp","ret"] and index+1 < len(ins):
                successors.append(ins[index+1].address)
            for target in successors:
                assert target in predecessors
                predecessors[target].append(index)

        def call_pushes(call_index):
            pending = [(p,[],set()) for p in predecessors[ins[call_index].address]]
            paths = []
            while pending:
                index,pushes,seen = pending.pop()
                assert index not in seen, "unexpected cycle in argument setup"
                i = ins[index]
                assert i.mnemonic != "call", "argument setup crossed another call"
                if i.mnemonic == "push":
                    pushes = pushes+[i]
                if len(pushes) == 4:
                    paths.append(pushes)
                else:
                    pending.extend((p,pushes,seen|{index}) for p in predecessors[i.address])
            assert len(paths) == 1
            return paths[0]  # destination, size, count, stream (reverse push order)

        groups = []
        fail_targets = set()
        for group_no in range(len(calls)//2):
            n,custom = calls[2*group_no]
            k,crt = calls[2*group_no+1]
            assert custom.operands[0].imm == 0x932c30 and crt.operands[0].imm == 0x945bfe
            # Both alternatives join immediately after the CRT call. Check the
            # actual unsigned return predicate; decompiler equality is weaker.
            cleanup,compare,branch = ins[k+1:k+4]
            assert cleanup.mnemonic == "add" and cleanup.op_str == "esp, 0x10"
            assert compare.mnemonic == "cmp" and compare.op_str == "eax, 1"
            assert branch.mnemonic == "jb"
            fail_targets.add(branch.operands[0].imm)
            pushes = [i for i in ins[:n] if i.mnemonic == "push"][-4:]
            assert pushes[1].op_str == "1"
            assert pushes[2].operands[0].type == X86_OP_IMM
            width = pushes[2].operands[0].imm
            custom_args,crt_args = call_pushes(n),call_pushes(k)
            for args in [custom_args,crt_args]:
                assert args[1].operands[0].type == X86_OP_IMM and args[1].operands[0].imm == width
                assert args[2].op_str == "1"
                assert args[3].op_str == pushes[0].op_str
            dest_reg = pushes[3].op_str
            assert pushes[3].operands[0].type == X86_OP_REG
            modes = [i for i in ins[:n] if i.mnemonic == "test"]
            mode_test = modes[-1]
            assert mode_test.op_str in ["ebx, ebx","eax, eax"]
            mode_branches = [i for i in ins[ins.index(mode_test)+1:n] if i.mnemonic == "je"]
            assert len(mode_branches) == 1
            zero_target = mode_branches[0].operands[0].imm
            assert custom.address < zero_target <= crt.address
            # Resolve the final pointer definition. The first transfer's scaled
            # record address is separately retained in selected entry sites.
            if group_no == 0:
                dest = 0
                repeat = 1
            else:
                defs = [i for i in ins[:n] if i.mnemonic in ["lea","add"] and
                        i.operands[0].type == X86_OP_REG and i.op_str.split(",")[0] == dest_reg]
                definition = defs[-1] if defs else None
                if definition and definition.mnemonic == "lea" and definition.operands[1].type == X86_OP_MEM:
                    mem = definition.operands[1].mem
                    reg = definition.reg_name(mem.base)
                    if reg == "esp":
                        dest = None
                    elif reg == record_reg:
                        assert not mem.index
                        dest = bias+mem.disp
                    else:
                        # Direct PUSH of the record register has no new LEA.
                        assert dest_reg == record_reg
                        dest = bias
                elif definition and definition.mnemonic == "add":
                    assert dest_reg == record_reg
                    dest = bias+definition.operands[1].imm
                else:
                    assert dest_reg == record_reg
                    dest = bias
                repeat = 1
                if dest_reg == "ebx" and start == 0x54dc90:
                    loop_compare = next(i for i in ins[k+4:] if i.mnemonic == "cmp")
                    assert loop_compare.operands[0].reg == capstone.x86.X86_REG_EBP
                    repeat = loop_compare.operands[1].imm
            groups.append({"destination_offset":dest,"width_bytes":width,"repeat":repeat,
                           "mode_test_va":f"{mode_test.address:08x}",
                           "size_push_va":f"{pushes[2].address:08x}",
                           "custom_call_va":f"{custom.address:08x}","crt_call_va":f"{crt.address:08x}",
                           "return_cmp_va":f"{compare.address:08x}","failure_branch_va":f"{branch.address:08x}"})
        actual = [(g["destination_offset"],g["width_bytes"],g["repeat"]) for g in groups]
        assert actual == expected(start), f"layout mismatch {entry}: {actual}"
        assert len(fail_targets) == 1
        stream_cursor = 0
        written = set()
        widen = {0x54dc90:[0x80],0x54e9a0:[8,10,12],0x54f150:[9,11,13],0x54ffd0:[0x69]}[start]
        widen_cursor = iter(widen)
        for g in groups:
            g["stream_offset"] = stream_cursor
            stream_cursor += g["width_bytes"]*g["repeat"]
            if g["destination_offset"] is None:
                g["scratch_then_word_offset"] = next(widen_cursor)
                written.update(range(g["scratch_then_word_offset"],g["scratch_then_word_offset"]+2))
            else:
                written.update(range(g["destination_offset"],g["destination_offset"]+g["width_bytes"]*g["repeat"]))
        # Keep all explicit non-stack stores/conversions and loop/exit gates,
        # plus entry arithmetic, without retaining the complete instruction body.
        selected = {}
        first_call = calls[0][1].address
        for i in ins:
            keep = i.address < first_call
            keep |= i.mnemonic in ["movzx","imul","ret","inc","shl"]
            keep |= i.mnemonic == "test" and i.op_str == "ax, ax"
            keep |= i.mnemonic == "mov" and i.op_str.startswith("ax, word ptr")
            keep |= i.mnemonic == "lea" and i.op_str.startswith("ebx, [edi")
            keep |= i.mnemonic == "add" and i.op_str.split(",")[0] in [record_reg,"ebx"]
            keep |= i.mnemonic == "cmp" and i.op_str != "eax, 1"
            keep |= i.mnemonic in ["jb","jbe","jne"] and i.operands[0].imm not in fail_targets
            keep |= i.mnemonic == "mov" and i.operands[0].type == X86_OP_MEM and i.reg_name(i.operands[0].mem.base) != "esp"
            keep |= i.address >= min(fail_targets)-12
            if keep:
                selected[f"{i.address:08x}"] = (i.mnemonic+" "+i.op_str).strip()
        refs = []
        for line in (exports/(entry+".refs")).read_text().splitlines():
            address,kind = line.split(None,1)
            refs.append({"site_va":address,"kind":kind})
        result.append({"entry_va":entry,"file_offset":f"{offset(start):08x}","body_bytes":size,
                       "instruction_count":len(ins),"body_sha256":digest(raw),"native_file_sha256":native_hashes,
                       "matched_native_instructions":len(ins),"incoming_refs":refs,
                       "record_stride":stride,"requested_bytes_per_complete_record":stream_cursor,
                       "calls_per_complete_record":sum(g["repeat"] for g in groups),
                       "untouched_destination_offsets":[x for x in range(stride) if x not in written],
                       "failure_epilogue_va":f"{min(fail_targets):08x}",
                       "field_groups":groups,"selected_instructions":selected})
    return {"specimen_sha256":PINNED,"native_manifest_sha256":MANIFEST,
            "method":"capstone==5.0.7; every owned instruction matched to native assembly; static extraction only",
            "address_space":"virtual addresses unless file_offset explicitly named",
            "field_group_note":"repeat means separate width-byte, count-one calls at consecutive width-byte destinations; null destination means caller stack scratch then explicit WORD conversion",
            "stream_offset_note":"sum of requested item sizes, not guaranteed physical file offset or compressed bytes consumed",
            "functions":result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("exports",type=Path)
    parser.add_argument("output",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.exports),indent=2)+"\n",encoding="utf-8",newline="\n")
