"""Verify four R18-A original-PE bodies against pinned native exports; emit no code bytes."""
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
MANIFEST_SHA = "fc4f2070cb0efa89c9473ebe507d0e2d3f01e1f5f66338177be5f34848ee7151"
PREFLIGHT_SHA = "8749c47798c3758dc7509d0b3b71b7147f169ee0390066f01ef023baf670bcbb"
SPECS = {0x6f0630:819, 0x6f4920:264, 0x6f56c0:282, 0x70d430:504}
INCOMING = {0x6f0630:[0x6f227b,0x6f4035,0x6f40ed],
    0x6f4920:[0x6f0b7e,0x6f24cb,0x6f4057,0x6f4253,0x6f42b1],
    0x6f56c0:[0x6f3f78], 0x70d430:[0x6f1f85]}
# Normal cleanup inferred from push/call/epilogue sequences, not a callee-body proof.
CLEANUP = {0x6c38c0:4,0x90cfc0:0,0x945640:0,0x6d6f70:28,
    0x6cd770:28,0x7172d0:4,0x6eecb0:4}
RNG = {0x6f4970:"360; coincident coordinates except (4,11)/(4,0)",
    0x6f49a7:"120; compare against snapshotted s8(p+10c)*s8(p+105)",
    0x6f49c1:"30; first heading-error draw",0x6f49ca:"30; second heading-error draw",
    0x70d45c:"F(s8(dword(p+6d)+21)+float32(p+a5)); addition in x87, no float32 intermediate store",
    0x70d465:"20; compare first result < second result",
    0x70d47f:"8; compare snapshotted s8(p+106) > result",
    0x70d4b9:"2; event1fe3 route",0x70d4c8:"10; event1fe3 route",
    0x70d505:"200; only after event1fe3 R(10)==0",
    0x70d552:"3; event216f route",0x70d561:"10; event216f route",
    0x70d57a:"200; only after event216f R(10)==0",
    0x70d5c6:"wrap32(30*s8(dword(p+69)+5a)+20); after action call and p+35 -=250",
    0x70d5d4:"3; only after preceding dynamic draw ==0"}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def hx(n):
    return f"{n:08x}"

def normalize(text):
    text=text.lower().replace("float ptr","dword ptr").replace("double ptr","qword ptr")
    text=re.sub(r"0x[0-9a-f]+",lambda m:str(int(m[0],16)),text)
    text=re.sub(r"st([0-7])",r"st(\1)",text.replace("*1",""))
    text=re.sub(r"\s+","",text).replace("+-","-").replace("+0]","]")
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
    manifest_raw=(args.exports/"manifest.json").read_bytes();preflight_raw=args.preflight.read_bytes()
    assert digest(manifest_raw)==MANIFEST_SHA,"export manifest SHA-256 mismatch"
    assert digest(preflight_raw)==PREFLIGHT_SHA,"annotation preflight SHA-256 mismatch"
    manifest=json.loads(manifest_raw);preflight=json.loads(preflight_raw)
    assert manifest["specimen_sha256"]==preflight["sha256"]==SHA
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
    for start,body_bytes in SPECS.items():
        old=[s for s in preflight["sites"] if s["address"]==hx(start)]
        assert len(old)==1 and old[0]["instruction_exists"] and old[0]["function_name"]=="FUN_"+hx(start)
        assert old[0].get("function_comment") in (None,"")
        # Decode the entire PE body independently, rather than only requesting export addresses.
        rows=list(md.disasm(read(start,body_bytes),start))
        assert sum(i.size for i in rows)==body_bytes
        exported=[(int(m[1],16),m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$",(args.exports/(hx(start)+".asm")).read_text(encoding="utf-8-sig"),re.M)]
        assert len(rows)==len(exported)
        for i,(address,asm) in zip(rows,exported):
            assert i.address==address and normalize(asm)==normalize(i.mnemonic+" "+i.op_str),(hx(i.address),asm,i.mnemonic,i.op_str)
        at={i.address:i for i in rows}
        selected={0x6f0630:{0x6f092a:("inc","byte ptr [edx + ecx + 0x8d46]")},
            0x6f4920:{0x6f4932:("sub","al, cl"),0x6f4936:("sub","cl, byte ptr [esp + 0x10]"),
                0x6f4983:("lea","edx, [ecx + eax*8]"),0x6f49df:("movsx","dx, byte ptr [eax + 0x3b]"),
                0x6f49e4:("movsx","ax, byte ptr [eax + 0x30]")},
            0x6f56c0:{0x6f578b:("fst","dword ptr [ecx + 0x4d]"),0x6f572e:("fstp","dword ptr [ecx + 0x4d]")},
            0x70d430:{0x70d5b7:("movsx","eax, byte ptr [eax + 0x5a]"),
                0x70d5bb:("lea","eax, [eax + eax*2]"),0x70d5be:("lea","ecx, [eax + eax*4]"),
                0x70d5c1:("lea","edx, [ecx + ecx + 0x14]"),0x70d5de:("neg","al")}}[start]
        for site,expected in selected.items():assert (at[site].mnemonic,at[site].op_str)==expected,hx(site)
        switches={}
        if start==0x6f56c0:
            table,selector=0x6f57dc,0x6f57e8
            targets=struct.unpack("<III",read(table,12));mapping=list(read(selector,28))
            assert targets==(0x6f5770,0x6f5756,0x6f57a5)
            assert max(mapping)<3 and at[0x6f574f].operands[0].mem.disp==table
            cases=[[n+0x13,hx(targets[k])] for n,k in enumerate(mapping)]
            assert [x[0] for x in cases if x[1]=="006f5770"]==[0x13,0x21]
            assert [x[0] for x in cases if x[1]=="006f5756"]==[0x15,0x24,0x2e]
            switches[0x6f574f]=dict(table=hx(table),selector=hx(selector),table_sha256=digest(read(table,12)),selector_sha256=digest(read(selector,28)),cases=cases,default="006f57a5")
        def successors(i):
            if i.mnemonic=="ret":return []
            ordinary=[i.address+i.size]
            if i.mnemonic.startswith("j"):
                targets=([i.operands[0].imm] if i.operands[0].type==CS_OP_IMM else [int(c[1],16) for c in switches[i.address]["cases"]])
                return list(dict.fromkeys(targets+([] if i.mnemonic=="jmp" else ordinary)))
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
            stop=leaders[n+1] if n+1<len(leaders) else start+body_bytes
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
        assert args_access=={0x6f0630:set(),0x6f4920:{(4,1),(8,1),(12,1),(16,1)},
            0x6f56c0:{(4,4),(8,2)},0x70d430:{(4,2),(4,4)}}[start]
        assert {i.operands[0].imm if i.operands else 0 for i in rows if i.mnemonic=="ret"}=={
            {0x6f0630:0,0x6f4920:16,0x6f56c0:8,0x70d430:4}[start]}
        stores=[i for i in rows if any(o.type==CS_OP_MEM and o.access&capstone.CS_AC_WRITE for o in i.operands) or (i.mnemonic.startswith(("fst","fist","fnst")) and i.operands and i.operands[0].type==CS_OP_MEM)]
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
        rng_addresses={int(r["site"],16) for r in rng};maximum={};active=set()
        def longest(site):
            if site not in maximum:
                assert site not in active,"unexpected local cycle"
                active.add(site)
                maximum[site]=int(site in rng_addresses)+max((longest(s) for s in successors(at[site])),default=0)
                active.remove(site)
            return maximum[site]
        upper=longest(start)
        assert upper=={0x6f0630:0,0x6f4920:4,0x6f56c0:0,0x70d430:8}[start]
        assert (len(rows),len(branches),len(calls),len(rng),len(state),sum(i.mnemonic=="ret" for i in rows))=={
            0x6f0630:(191,35,2,0,38,1),0x6f4920:(78,12,4,4,7,2),
            0x6f56c0:(70,13,0,0,5,2),0x70d430:(167,12,20,11,3,4)}[start]
        incoming=[]
        for site in INCOMING[start]:
            i=next(md.disasm(read(site,5),site,count=1))
            assert i.mnemonic=="call" and i.operands[0].imm==start
            incoming.append(dict(site=hx(site),instruction_sha256=digest(read(site,5))))
        comparisons=[];constants=set()
        for i in rows:
            if i.mnemonic=="fcomp":
                follow=[];cursor=i.address+i.size
                for _ in range(8):
                    j=at[cursor];follow.append(j)
                    if j.mnemonic in ("je","jne"):break
                    ss=successors(j);assert len(ss)==1
                    cursor=ss[0]
                test=next((j for j in follow if j.mnemonic=="test" and j.op_str.startswith("ah,")),None)
                branch=next((j for j in follow if j.mnemonic in ("je","jne")),None)
                assert test and branch
                nonzero,zero={1:("less or unordered","ordered greater or equal"),0x41:("less, equal or unordered","ordered greater")}[test.operands[1].imm]
                comparisons.append(dict(site=hx(i.address),operand=i.op_str,test=hx(test.address),mask=test.operands[1].imm,branch=hx(branch.address),target=hx(branch.operands[0].imm),relation=nonzero if branch.mnemonic=="jne" else zero))
            if i.mnemonic.startswith("f"):
                for o in i.operands:
                    if o.type==CS_OP_MEM and not o.mem.base and not o.mem.index and 0x960000<=o.mem.disp<0x980000:constants.add((o.mem.disp,o.size))
        functions.append(dict(entry=hx(start),native_body_bytes=body_bytes,admitted_body_bytes=body_bytes,
            end_exclusive=hx(start+body_bytes),file_offset=f"0x{offset(start,body_bytes):x}",body_sha256=digest(read(start,body_bytes)),
            instruction_count=len(rows),branch_count=len(branches),call_count=len(calls),rng_site_count=len(rng),nonframe_store_count=len(state),
            all_exported_instructions_match=True,native_exports={ext:manifest["files"][hx(start)+"."+ext]["sha256"] for ext in ("asm","c")},
            verified_R17_incoming_calls=incoming,incoming_list_exhaustive=False,
            branches=branches,switches=[dict(site=hx(s),**v) for s,v in switches.items()],
            direct_calls=[dict(target=t,count=len(s),sites=s) for t,s in sorted(targets.items())],
            normal_stack_check=dict(all_instruction_joins_balanced=True,all_returns_restore_entry_esp=True,entry_stack_accesses=[list(x) for x in sorted(args_access)],call_site_columns=["site","esp_delta_before_call","inferred_callee_cleanup_bytes"],call_sites=sorted(call_depths),limitation="Normal cleanup inferred from local sequences, not transitive behavior or exceptional exits"),
            returns=[[hx(i.address),i.operands[0].imm if i.operands else 0] for i in rows if i.mnemonic=="ret"],
            nonframe_stores=[dict(site=hx(i.address),operation=i.mnemonic,destination=i.op_str.split(",")[0],width_bytes=i.operands[0].size,source=i.op_str.split(",",1)[1].strip() if "," in i.op_str else None) for i in state],
            frame_store_sites=[hx(i.address) for i in stores if i not in state],rng_sites=rng,x87_comparisons=comparisons,
            cfg=dict(all_blocks_structurally_reachable=True,acyclic=True,block_count=len(blocks),block_columns=["start","end_exclusive","successors"],blocks=[[hx(b),hx(v[-1].address+v[-1].size),[hx(s) for s in edges[b]]] for b,v in blocks.items()],upper_direct_rng_calls=upper,upper_limit="Structural maximum ignoring correlated conditions; excludes every callee's internal RNG"),
            constants=[dict(address=hx(a),width_bytes=w,value=struct.unpack("<"+{4:"f",8:"d"}[w],read(a,w))[0],sha256=digest(read(a,w))) for a,w in sorted(constants)]))
    return dict(work_unit="R18-A",specimen_sha256=SHA,export_manifest_sha256=MANIFEST_SHA,annotation_preflight_sha256=PREFLIGHT_SHA,checkpoint_archive_sha256=manifest["checkpoint_archive_sha256"],evidence_class="complete local static instruction mapping; no execution oracle",decoder="Capstone 5.0.7 x86-32",address_kind="virtual; raw file offsets labelled",functions=functions,limits=["Callee writes, RNG, aliases and abnormal returns remain boundaries","Structural reachability does not establish runtime feasibility","Runtime x87 control, exceptional inputs and connected gameplay unmeasured"])

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("binary",type=Path)
    p.add_argument("--exports",type=Path,required=True);p.add_argument("--preflight",type=Path,required=True)
    p.add_argument("--output",type=Path,default=Path("evidence/match-helpers-18-sites.json"))
    args=p.parse_args();args.output.write_text(compact(run(args))+"\n",encoding="utf-8",newline="\n")
    print(f"wrote {args.output}; static decoder check only")
