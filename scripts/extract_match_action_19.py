"""Independently decode two R19-A PE bodies and compare pinned native exports.

Outputs addresses, digests and selected semantic sites, never original code bytes.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "3c5da196118b891f3dcd84f8126355d3c36888c3c7b72ca1f6d89772d8a22935"
PREFLIGHT_SHA = "a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78"
SPECS = {0x6cd770:685, 0x6cd490:346}
CLEANUP = {0x6f0970:0, 0x90cfc0:0, 0x7160d0:4, 0x70c040:4,
           0x70a910:4, 0x6cd490:4, 0x6d6f70:28}
RNG = {
    0x6cd7b1:"2; only side low byte==ff, then side byte=(EAX==0)",
    0x6cd7da:"4; only flag==0 and current signed x outside2..6; nonzero selects exterior x",
    0x6cd803:"s8(kind)+1; exterior path y subtraction",
    0x6cd811:"s8(kind)+1; exterior path y addition",
    0x6cd826:"s8(kind)+1; ordinary/retry x subtraction",
    0x6cd834:"s8(kind)+1; ordinary/retry x addition",
    0x6cd840:"s8(kind)+1; ordinary/retry y subtraction",
    0x6cd84e:"s8(kind)+1; ordinary/retry y addition",
    0x6cd87a:"s8(kind)+1; if kind!=0, store low8(EAX+1) in m+8eaa",
    0x6cd8cd:"4; after heading store, before coordinate/side commit",
    0x6cd968:"3; each admitted slot in optional two-side/twenty-slot scan",
    0x6cd976:"2; only preceding R(3)==0; full result forwarded to007160d0",
    0x6cd9b9:"4; only last!=0 and current x==4 and y is ff or0c"
}

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def hx(n):
    return f"{n:08x}"

def normalize(text):
    text=text.lower()
    text=re.sub(r"0x[0-9a-f]+",lambda m:str(int(m[0],16)),text)
    text=re.sub(r"\s+","",text).replace("*1", "").replace("+-","-").replace("+0]","]")
    for old,new in (("jnz","jne"),("jz","je"),("setz","sete"),("setnz","setne")):
        if text.startswith(old):text=new+text[len(old):]
    return text

def compact(value,level=0):
    encoded=json.dumps(value)
    if len(encoded)<=220:return encoded
    pad,child="  "*level,"  "*(level+1)
    if isinstance(value,dict):return "{\n"+",\n".join(child+json.dumps(k)+": "+compact(v,level+1) for k,v in value.items())+"\n"+pad+"}"
    if isinstance(value,list):return "[\n"+",\n".join(child+compact(v,level+1) for v in value)+"\n"+pad+"]"
    return encoded

def run(args):
    data=args.binary.read_bytes()
    assert digest(data)==SHA,"specimen SHA-256 mismatch"
    assert capstone.__version__=="5.0.7"
    manifest_raw=(args.exports/"manifest.json").read_bytes()
    preflight_raw=args.preflight.read_bytes()
    assert digest(manifest_raw)==MANIFEST_SHA,"export manifest SHA-256 mismatch"
    assert digest(preflight_raw)==PREFLIGHT_SHA,"annotation preflight SHA-256 mismatch"
    manifest=json.loads(manifest_raw);preflight=json.loads(preflight_raw)
    assert manifest["specimen_sha256"]==preflight["sha256"]==SHA
    assert manifest["preflight_sha256"]==PREFLIGHT_SHA
    for name,meta in manifest["files"].items():
        raw=(args.exports/name).read_bytes()
        assert len(raw)==meta["bytes"] and digest(raw)==meta["sha256"],name
    pe=struct.unpack_from("<I",data,0x3c)[0]
    assert data[:2]==b"MZ" and data[pe:pe+4]==b"PE\0\0"
    assert struct.unpack_from("<H",data,pe+4)[0]==0x14c
    count=struct.unpack_from("<H",data,pe+6)[0];optsize=struct.unpack_from("<H",data,pe+20)[0]
    optional=pe+24
    assert struct.unpack_from("<H",data,optional)[0]==0x10b
    base=struct.unpack_from("<I",data,optional+28)[0]
    sections=[struct.unpack_from("<IIII",data,optional+optsize+40*n+8)[1:] for n in range(count)]
    def offset(va,size):
        for rva,length,raw in sections:
            delta=va-base-rva
            if 0<=delta and delta+size<=length:return raw+delta
        raise ValueError("range not backed by raw PE section")
    def read(va,size):
        pos=offset(va,size);return data[pos:pos+size]
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    functions=[]
    for start,length in SPECS.items():
        old=[s for s in preflight["sites"] if s["address"]==hx(start)]
        assert len(old)==1 and old[0]["instruction_exists"]
        assert old[0]["function_name"]=="FUN_"+hx(start)
        assert old[0].get("function_comment") in (None,"")
        rows=list(md.disasm(read(start,length),start))
        assert sum(i.size for i in rows)==length
        exported=[(int(m[1],16),m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$",(args.exports/(hx(start)+".asm")).read_text(encoding="utf-8-sig"),re.M)]
        assert len(rows)==len(exported)
        for i,(address,asm) in zip(rows,exported):
            assert i.address==address and normalize(asm)==normalize(i.mnemonic+" "+i.op_str),(hx(i.address),asm,i.mnemonic,i.op_str)
        at={i.address:i for i in rows}
        selected={0x6cd770:{0x6cd7f6:("mov","byte ptr [esp + 0x14], al"),
            0x6cd85e:("je","0x6cd869"),0x6cd862:("jl","0x6cd81d"),
            0x6cd867:("jg","0x6cd81d"),0x6cd8bc:("mov","ax, word ptr [edx*2 + 0xb67c30]"),
            0x6cd98c:("dec","ebp"),0x6cd991:("cmp","bl, 2"),
            0x6cd9d6:("push","0x3f800000"),0x6cd9eb:("push","0x3f800000")},
            0x6cd490:{0x6cd4d0:("jge","0x6cd5b4"),0x6cd4de:("jge","0x6cd545"),
            0x6cd547:("jl","0x6cd5ae"),0x6cd5c4:("sete","al"),
            0x6cd5c9:("push","eax"),0x6cd5ae:("xor","al, al")}}[start]
        for site,expected in selected.items():
            assert (at[site].mnemonic,at[site].op_str)==expected,(hx(site),expected)
        def successors(i):
            if i.mnemonic=="ret":return []
            ordinary=[i.address+i.size]
            if i.mnemonic.startswith("j"):
                assert i.operands[0].type==CS_OP_IMM
                return [i.operands[0].imm]+([] if i.mnemonic=="jmp" else ordinary)
            return ordinary
        branches=[];leaders={start}
        for i in rows:
            ss=successors(i)
            assert all(s in at for s in ss),(hx(i.address),ss)
            if i.mnemonic.startswith("j"):
                leaders.update(ss)
                if i.address+i.size in at:leaders.add(i.address+i.size)
                branches.append([hx(i.address),i.mnemonic,[hx(s) for s in ss]])
            elif i.mnemonic=="ret" and i.address+i.size in at:leaders.add(i.address+i.size)
        leaders=sorted(leaders);blocks={}
        for n,b in enumerate(leaders):
            stop=leaders[n+1] if n+1<len(leaders) else start+length
            blocks[b]=[i for i in rows if b<=i.address<stop]
        edges={b:successors(items[-1]) for b,items in blocks.items()}
        reached=set();todo=[start]
        while todo:
            b=todo.pop()
            if b not in reached:reached.add(b);todo.extend(edges[b])
        assert reached==set(blocks)
        calls=[i for i in rows if i.mnemonic=="call"]
        assert all(i.operands[0].type==CS_OP_IMM for i in calls)
        targets=defaultdict(list)
        for i in calls:targets[hx(i.operands[0].imm)].append(hx(i.address))
        stack_at={};todo=[(start,0)];args_access=set();call_depths=[]
        while todo:
            site,delta=todo.pop()
            if site in stack_at:
                assert stack_at[site]==delta,(hx(site),delta,stack_at[site]);continue
            stack_at[site]=delta;i=at[site]
            for o in i.operands:
                if o.type==CS_OP_MEM and i.reg_name(o.mem.base)=="esp" and delta+o.mem.disp>=0:
                    args_access.add((delta+o.mem.disp,o.size))
            if i.mnemonic=="push":delta-=4
            elif i.mnemonic=="pop":delta+=4
            elif i.mnemonic in ("add","sub") and i.op_str.startswith("esp,"):
                delta+=i.operands[1].imm*(1 if i.mnemonic=="add" else -1)
            elif i.mnemonic=="call":
                cleanup=CLEANUP[i.operands[0].imm];call_depths.append([hx(site),delta,cleanup]);delta+=cleanup
            todo.extend((s,delta) for s in successors(i))
        assert len(stack_at)==len(rows)
        assert all(stack_at[i.address]==0 for i in rows if i.mnemonic=="ret")
        assert args_access=={0x6cd770:{(4,1),(8,1),(12,1),(16,1),(16,4),(20,1),(24,1),(28,4)},0x6cd490:{(4,1)}}[start],args_access
        assert {i.operands[0].imm for i in rows if i.mnemonic=="ret"}=={28 if start==0x6cd770 else 4}
        stores=[i for i in rows if any(o.type==CS_OP_MEM and o.access&capstone.CS_AC_WRITE for o in i.operands)]
        state=[i for i in stores if i.reg_name(i.operands[0].mem.base)!="esp"]
        predecessors=defaultdict(list)
        for i in rows:
            for s in successors(i):predecessors[s].append(i.address)
        rng=[]
        for i in calls:
            if i.operands[0].imm!=0x90cfc0:continue
            todo=list(predecessors[i.address]);seen=set();pushes=set()
            while todo:
                b=todo.pop()
                if b in seen:continue
                seen.add(b);j=at[b]
                if j.mnemonic=="push":pushes.add(b);continue
                assert j.mnemonic not in ("call","pop","ret")
                todo.extend(predecessors[b])
            assert len(pushes)==1
            j=at[pushes.pop()]
            rng.append(dict(site=hx(i.address),argument_push=hx(j.address),bound_operand=j.op_str,bound=RNG[i.address]))
        assert (len(rows),len(branches),len(calls),len(rng),len(state),sum(i.mnemonic=="ret" for i in rows))=={
            0x6cd770:(216,36,19,13,11,1),0x6cd490:(102,9,6,0,11,6)}[start]
        incoming=[]
        for site in {0x6cd770:[0x70d4f4,0x70d531,0x70d5a9],0x6cd490:[0x6cda13]}[start]:
            i=next(md.disasm(read(site,5),site,count=1))
            assert i.mnemonic=="call" and i.operands[0].imm==start,hx(site)
            incoming.append(dict(site=hx(site),instruction_sha256=digest(read(site,5))))
        functions.append(dict(entry=hx(start),native_body_bytes=length,admitted_body_bytes=length,
            body_ranges=[[hx(start),hx(start+length)]],range_end_kind="exclusive",
            file_offset=f"0x{offset(start,length):x}",body_sha256=digest(read(start,length)),
            instruction_count=len(rows),branch_count=len(branches),call_count=len(calls),rng_site_count=len(rng),nonframe_store_count=len(state),
            all_exported_instructions_match=True,native_exports={ext:manifest["files"][hx(start)+"."+ext]["sha256"] for ext in ("asm","c")},
            supplied_incoming_calls=incoming,incoming_list_exhaustive=False,branches=branches,
            direct_calls=[dict(target=t,count=len(s),sites=s) for t,s in sorted(targets.items())],
            normal_stack_check=dict(all_instruction_joins_balanced=True,all_returns_restore_entry_esp=True,
                entry_stack_accesses=[list(x) for x in sorted(args_access)],call_site_columns=["site","esp_delta_before_call","inferred_callee_cleanup_bytes"],
                call_sites=sorted(call_depths),limitation="Normal cleanup inferred from local sequences; no exceptional-exit or transitive proof"),
            returns=[[hx(i.address),i.operands[0].imm] for i in rows if i.mnemonic=="ret"],
            nonframe_stores=[dict(site=hx(i.address),operation=i.mnemonic,destination=i.op_str.split(",")[0],width_bytes=i.operands[0].size,
                source=i.op_str.split(",",1)[1].strip() if "," in i.op_str else None) for i in state],
            frame_store_sites=[hx(i.address) for i in stores if i not in state],rng_sites=rng,
            cfg=dict(all_blocks_structurally_reachable=True,block_count=len(blocks),block_columns=["start","end_exclusive","successors"],
                blocks=[[hx(b),hx(v[-1].address+v[-1].size),[hx(s) for s in edges[b]]] for b,v in blocks.items()],
                backward_edges=[[hx(i.address),hx(s)] for i in rows for s in successors(i) if s<=i.address],
                finite_total_direct_rng_bound=None if start==0x6cd770 else 0,
                limit="006cd770 retry can consume four draws per iteration without a local iteration cap; optional slot scan is bounded to2*20 entries; excludes every transitive call")))
    return dict(work_unit="R19-A",specimen_sha256=SHA,export_manifest_sha256=MANIFEST_SHA,
        annotation_preflight_sha256=PREFLIGHT_SHA,checkpoint_archive_sha256=manifest["checkpoint_archive_sha256"],
        evidence_class="complete local static instruction mapping; no execution oracle",decoder="Capstone 5.0.7 x86-32",
        address_kind="virtual; raw file offsets labelled",functions=functions,
        limits=["Callee writes/RNG/failures remain boundaries", "Structural reachability does not prove runtime feasibility or termination",
                "No table payload, game data, native project or numerical outcome equivalence supplied"])

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("binary",type=Path)
    p.add_argument("--exports",type=Path,required=True);p.add_argument("--preflight",type=Path,required=True)
    p.add_argument("--output",type=Path,default=Path("evidence/match-action-19-sites.json"))
    args=p.parse_args();args.output.write_text(compact(run(args))+"\n",encoding="utf-8",newline="\n")
    print(f"wrote {args.output}; static decoder check only")
