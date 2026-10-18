"""Verify R17-A's complete native body sets; emit compact static evidence, never code bytes."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "096c06e07891855555057cdcc9f33307c6cdee79e7c632be5f593f76d894a2b8"
PREFLIGHT_SHA = "0d084f0348af44eeb24a73d8cec0fc866525099b14180bd87bd9c6246beda10f"
SPECS = {0x6fa250:576, 0x6fa490:2222, 0x6f09f0:14526}
INCOMING = {0x6fa250:[0x710b7c,0x710c4f,0x710d0c,0x710e0a,0x710f81,0x7137da],
 0x6fa490:[0x711e3f,0x711e50,0x711f2e,0x7134ce,0x71371d,0x71372e,0x7137a7,0x7139e7],
 0x6f09f0:[0x71395c,0x713b82,0x713bb0]}
# (jump, target table, target count, input first, byte selector map, input count)
SWITCHES = [(0x6f0da2,0x6f42c4,4,1,0x6f42d4,32),
 (0x6f1479,0x6f42f4,12,1,0x6f4324,46),
 (0x6f1632,0x6f4354,4,2,0,4),
 (0x6f1f75,0x6f4364,6,1,0x6f437c,45),
 (0x6f1fd2,0x6f43ac,12,1,0x6f43dc,46),
 (0x6f2186,0x6f440c,11,0,0,11),
 (0x6f3ca0,0x6f4438,7,1,0x6f4454,64)]
# Inferred normal callee stack cleanup, checked at every local instruction join.
CLEANUP = {0x5b5270:4,0x5e8290:0,0x600a50:0,0x68d0d0:8,
 0x6bb8d0:8,0x6bb9a0:36,0x6bce20:12,0x6c38c0:4,0x6c38f0:4,
 0x6c3950:16,0x6c87e0:36,0x6cb650:4,0x6cb910:4,0x6cb930:8,
 0x6cd490:4,0x6cd5f0:4,0x6cd770:28,0x6cda20:8,0x6ceb90:12,
 0x6cfc60:28,0x6cfcd0:32,0x6cfd70:16,0x6cfe10:20,0x6d6f70:28,
 0x6eecb0:4,0x6f0630:0,0x6f09b0:8,0x6f4920:16,0x6f56c0:8,
 0x6fa140:8,0x6fad40:28,0x70d430:4,0x7103e0:0,0x714d40:0,
 0x716c90:0,0x716e10:4,0x7172d0:4,0x7c1e30:16,0x90cfc0:0,
 0x90d130:0,0x944c9f:0,0x944cff:0,0x945640:0}
RNG_DYNAMIC = {
 0x6fa2f8:"F(2*grid2*float32(grid1)); two separate 006f09b0 calls for candidate to its selected end",
 0x6fa3b6:"80; compare signed product of snapshotted candidate bytes+105/+107 > EAX",
 0x6fac14:"F(2*g*g); two direct original grid loads for candidate to its selected end",
 0x6f0cf8:"trunc_s32(wrap32((10000-s16(low16(F(float32(p+4d))))) squared)/50000)",
 0x6f0d80:"wrap32(selected_s16(p+138/+13e/+13c)-s16(low16(draw at006f0cf8))+s16(p+19c))",
 0x6f0e04:"wrap32(50*s8(m+8ea9) cubed)",
 0x6f0e23:"trunc_s32(s16(p+29)/10)-30; directly follows006f0e04",
 0x6f1395:"s16(other+31); bypassed by 006cb650 AL or output byte body+30",
 0x6f1772:"s8(dword(other+69)+5a)+6",
 0x6f19e8:"s8(output body+40); after R(4)==0, before R(20)",
 0x6f1edb:"F(float32(p+e5)*float32(5)+float32(75)); mode!=4 and signed score<1",
 0x6f1f2e:"s16(other+31); bypassed by helper predicate or output body+30",
 0x6f22f4:"30*s8(dword(p+69)+5a)+20",
 0x6f241b:"3-(R(10)<snapshot_s8(other+10d))-(R(10)<snapshot_s8(other+10c)); ordered draws006f23ef,006f2409",
 0x6f27b8:"30*s8(other+17)+50",
 0x6f2882:"s16(p+31)",
 0x6f2b51:"20*(s8(p+17)+1)",
 0x6f2ce3:"F(float32(p+95)); followed by006f2cec R(30)",
 0x6f3311:"F(float32(p+95)); followed by006f331a R(30)",
 0x6f3a3b:"20*(s8(dword(p+69)+5a)+1)"}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def hx(n):
    return f"{n:08x}"

def normalize(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = text.replace("dword ptr fs:", "fs:")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), text)
    text = re.sub(r"st([0-7])",r"st(\1)",text.replace("*1", ""))
    text = re.sub(r"\s+", "", text).replace("+-", "-").replace("+0]", "]")
    if text in ("fcomp", "faddp", "fsubp", "fmulp", "fdivp", "fxch"):
        text += "st(1)"
    for old,new in (("jnz","jne"),("jz","je"),("setz","sete"),("setnz","setne")):
        if text.startswith(old):
            text = new+text[len(old):]
    return text

def compact(value, level=0):
    encoded = json.dumps(value)
    if len(encoded) <= 220:
        return encoded
    pad,child = "  "*level,"  "*(level+1)
    if isinstance(value,dict):
        return "{\n"+",\n".join(child+json.dumps(k)+": "+compact(v,level+1) for k,v in value.items())+"\n"+pad+"}"
    if isinstance(value,list):
        return "[\n"+",\n".join(child+compact(v,level+1) for v in value)+"\n"+pad+"]"
    return encoded

def run(args):
    data=args.binary.read_bytes()
    assert digest(data)==SHA,"specimen SHA-256 mismatch"
    assert capstone.__version__=="5.0.7"
    manifest_raw=(args.exports/"manifest.json").read_bytes()
    preflight_raw=args.preflight.read_bytes()
    assert digest(manifest_raw)==MANIFEST_SHA,"export manifest SHA-256 mismatch"
    assert digest(preflight_raw)==PREFLIGHT_SHA,"annotation preflight SHA-256 mismatch"
    manifest=json.loads(manifest_raw)
    preflight=json.loads(preflight_raw)
    assert manifest["specimen_sha256"]==preflight["sha256"]==SHA
    for name,meta in manifest["files"].items():
        raw=(args.exports/name).read_bytes()
        assert len(raw)==meta["bytes"] and digest(raw)==meta["sha256"],name
    pe=struct.unpack_from("<I",data,0x3c)[0]
    assert data[:2]==b"MZ" and data[pe:pe+4]==b"PE\0\0"
    assert struct.unpack_from("<H",data,pe+4)[0]==0x14c
    count=struct.unpack_from("<H",data,pe+6)[0]
    optsize=struct.unpack_from("<H",data,pe+20)[0]
    optional=pe+24
    assert struct.unpack_from("<H",data,optional)[0]==0x10b
    base=struct.unpack_from("<I",data,optional+28)[0]
    sections=[struct.unpack_from("<IIII",data,optional+optsize+40*n+8)[1:] for n in range(count)]
    def offset(va,size):
        for rva,length,raw in sections:
            delta=va-base-rva
            if 0<=delta and delta+size<=length:
                return raw+delta
        raise ValueError("range not backed by raw PE section")
    def read(va,size):
        pos=offset(va,size)
        return data[pos:pos+size]
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    functions=[]
    sys.setrecursionlimit(20000)
    for start,expected_bytes in SPECS.items():
        incoming=[]
        for site in INCOMING[start]:
            i=next(md.disasm(read(site,5),site,count=1))
            assert i.mnemonic=="call" and i.operands[0].type==CS_OP_IMM and i.operands[0].imm==start
            incoming.append(dict(site=hx(site),instruction_sha256=digest(read(site,5))))
        old=[s for s in preflight["sites"] if s["address"]==hx(start)]
        assert len(old)==1 and old[0]["instruction_exists"] and old[0]["function_name"]=="FUN_"+hx(start)
        exported=[(int(m[1],16),m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$",(args.exports/(hx(start)+".asm")).read_text(encoding="utf-8-sig"),re.M)]
        rows=[];ranges=[]
        for address,asm in exported:
            i=next(md.disasm(read(address,15),address,count=1))
            assert normalize(asm)==normalize(i.mnemonic+" "+i.op_str),(hx(address),asm,i.mnemonic,i.op_str)
            if ranges and ranges[-1][1]==address:
                ranges[-1][1]=address+i.size
            else:
                if ranges: assert ranges[-1][1]<address
                ranges.append([address,address+i.size])
            rows.append(i)
        assert sum(b-a for a,b in ranges)==expected_bytes
        native_ranges=[r[:] for r in ranges]
        closure=[]
        if start==0x6f09f0:
            assert ranges==[[0x6f09f0,0x6f1639],[0x6f164e,0x6f42c3]]
            closure=list(md.disasm(read(0x6f1639,21),0x6f1639))
            assert [(i.address,i.mnemonic,i.op_str) for i in closure]==[
                (0x6f1639,"mov","ebx, 0x1ff6"),(0x6f163e,"jmp","0x6f1670"),
                (0x6f1640,"mov","ebx, 0x1ff7"),(0x6f1645,"jmp","0x6f1670"),
                (0x6f1647,"mov","ebx, 0x1ff9"),(0x6f164c,"jmp","0x6f1670")]
            rows=sorted(rows+closure,key=lambda i:i.address)
            ranges=[[0x6f09f0,0x6f42c3]]
        at={i.address:i for i in rows};positions={i.address:n for n,i in enumerate(rows)}
        if start==0x6f09f0:
            selected={0x6f0a68:("xor","al, al"),0x6f0a6c:("mov","byte ptr [esp + 0x12], al"),
                0x6f0ae0:("inc","al"),0x6f0ae2:("cmp","al, cl"),0x6f0ae8:("jl","0x6f0a76"),
                0x6f0bfd:("inc","al"),0x6f0bff:("cmp","al, cl"),0x6f0c05:("jl","0x6f0b93"),
                0x6f3c73:("inc","al"),0x6f3c75:("cmp","al, cl"),0x6f3c7b:("jl","0x6f3c09"),
                0x6f279b:("movsx","eax, byte ptr [edi + 0x17]"),
                0x6f27a8:("lea","eax, [eax + eax*2]"),
                0x6f27b0:("lea","eax, [eax + eax*4]"),
                0x6f27b3:("lea","ecx, [eax + eax + 0x32]"),
                0x6f27b7:("push","ecx"),0x6f27b8:("call","0x90cfc0")}
            for site,expected in selected.items():
                assert (at[site].mnemonic,at[site].op_str)==expected,hx(site)
        switches={}
        for site,table,n,first,selector,inputs in SWITCHES:
            if site not in at: continue
            i=at[site]
            assert i.mnemonic=="jmp" and i.operands[0].mem.disp==table and i.operands[0].mem.scale==4
            targets=struct.unpack("<"+"I"*n,read(table,4*n))
            assert all(t in at for t in targets),(hx(site),[hx(t) for t in targets if t not in at])
            if site==0x6f1632:
                assert targets==(0x6f1647,0x6f1640,0x6f164e,0x6f1639)
            mapping=list(read(selector,inputs)) if selector else list(range(inputs))
            assert max(mapping)<n
            switches[site]=dict(table=hx(table),table_sha256=digest(read(table,4*n)),
                selector_table=hx(selector) if selector else None, selector_sha256=digest(read(selector,inputs)) if selector else None,
                cases=[[j+first,hx(targets[k])] for j,k in enumerate(mapping)])
        def successors(i):
            if i.mnemonic=="ret": return []
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
        for a,b in ranges: leaders.add(a)
        leaders=sorted(leaders);blocks={};owner={}
        for n,b in enumerate(leaders):
            stop=leaders[n+1] if n+1<len(leaders) else ranges[-1][1]
            items=[i for i in rows if b<=i.address<stop]
            blocks[b]=items;owner.update((i.address,b) for i in items)
        edges={b:successors(items[-1]) for b,items in blocks.items()}
        reached=set();todo=[start]
        while todo:
            b=todo.pop()
            if b not in reached:reached.add(b);todo.extend(edges[b])
        assert reached==set(blocks),[hx(b) for b in set(blocks)-reached]
        index={};low={};stack=[];active=set();sccs=[]
        def visit(b):
            index[b]=low[b]=len(index);stack.append(b);active.add(b)
            for s in edges[b]:
                if s not in index:visit(s);low[b]=min(low[b],low[s])
                elif s in active:low[b]=min(low[b],index[s])
            if low[b]==index[b]:
                c=[]
                while True:
                    s=stack.pop();active.remove(s);c.append(s)
                    if s==b:break
                sccs.append(sorted(c))
        visit(start)
        calls=[i for i in rows if i.mnemonic=="call"]
        assert all(i.operands[0].type==CS_OP_IMM for i in calls)
        targets=defaultdict(list)
        for i in calls: targets[hx(i.operands[0].imm)].append(hx(i.address))
        stack_at={};todo=[(start,0)];args_access=set();call_depths=[]
        while todo:
            site,delta=todo.pop()
            if site in stack_at:
                assert stack_at[site]==delta,(hx(site),delta,stack_at[site])
                continue
            stack_at[site]=delta;i=at[site]
            for o in i.operands:
                if o.type==CS_OP_MEM and i.reg_name(o.mem.base)=="esp" and delta+o.mem.disp>=0:
                    args_access.add((delta+o.mem.disp,o.size))
            if i.mnemonic=="ret":pass
            elif i.mnemonic=="push":delta-=4
            elif i.mnemonic=="pop":delta+=4
            elif i.mnemonic in ("add","sub") and i.op_str.startswith("esp,"):
                delta+=i.operands[1].imm*(1 if i.mnemonic=="add" else -1)
            elif i.mnemonic=="call":
                target=i.operands[0].imm
                call_depths.append([hx(site),delta,CLEANUP[target]])
                delta+=CLEANUP[target]
            todo.extend((s,delta) for s in successors(i))
        assert len(stack_at)==len(rows)
        assert all(stack_at[i.address]==0 for i in rows if i.mnemonic=="ret"),[(hx(i.address),stack_at[i.address]) for i in rows if i.mnemonic=="ret"]
        assert args_access=={0x6fa250:{(4,4),(8,4),(12,1),(12,4),(16,4),(20,1),(20,4)},
            0x6fa490:{(4,1),(8,1)},0x6f09f0:{(4,4),(8,1),(8,4),(12,2),(12,4),(16,1),(20,1)}}[start]
        stores=[i for i in rows if any(o.type==CS_OP_MEM and o.access&capstone.CS_AC_WRITE for o in i.operands) or (i.mnemonic.startswith(("fst","fist","fnst")) and i.operands and i.operands[0].type==CS_OP_MEM)]
        state=[i for i in stores if any(o.type==CS_OP_MEM and i.reg_name(o.mem.base)!="esp" and (o.access&capstone.CS_AC_WRITE or i.mnemonic.startswith(("fst","fist","fnst"))) for o in i.operands)]
        predecessors=defaultdict(list)
        for i in rows:
            for s in successors(i):predecessors[s].append(i.address)
        def push_origin(site):
            todo=list(predecessors[site]);seen=set();found=set()
            while todo:
                b=todo.pop()
                if b in seen:continue
                seen.add(b);j=at[b]
                if j.mnemonic=="push":found.add(b);continue
                assert j.mnemonic not in ("call","pop","ret") and not(j.mnemonic in ("add","sub","mov") and j.op_str.startswith("esp,")),hx(site)
                todo.extend(predecessors[b])
            assert len(found)==1,(hx(site),found)
            return at[found.pop()]
        rng=[]
        for i in calls:
            if i.operands[0].imm==0x90cfc0:
                j=push_origin(i.address)
                rng.append(dict(site=hx(i.address),block=hx(owner[i.address]),argument_push=hx(j.address),bound_operand=j.op_str,
                    bound=RNG_DYNAMIC.get(i.address,str(j.operands[0].imm) if j.operands[0].type==CS_OP_IMM else None)))
        assert all(r["bound"] is not None for r in rng)
        cycles=[c for c in sccs if len(c)>1 or c[0] in edges[c[0]]]
        component_of={b:n for n,c in enumerate(sccs) for b in c}
        dag={n:sorted({component_of[s] for b in c for s in edges[b] if component_of[s]!=n}) for n,c in enumerate(sccs)}
        rng_addrs={int(r["site"],16) for r in rng}
        weights={n:sum(i.address in rng_addrs for b in c for i in blocks[b])*(127 if c in cycles and start==0x6f09f0 else 1) for n,c in enumerate(sccs)}
        maximum={}
        def longest(n):
            if n not in maximum:maximum[n]=weights[n]+max((longest(s) for s in dag[n]),default=0)
            return maximum[n]
        upper=longest(component_of[start])
        assert upper=={0x6fa250:2,0x6fa490:7,0x6f09f0:146}[start]
        assert len(cycles)=={0x6fa250:0,0x6fa490:2,0x6f09f0:3}[start]
        expected={0x6fa250:(176,15,10,2,13,2),0x6fa490:(678,109,44,37,9,2),0x6f09f0:(4489,846,203,59,93,6)}[start]
        assert (len(rows),len(branches),len(calls),len(rng),len(state),sum(i.mnemonic=="ret" for i in rows))==expected
        comparisons=[]
        for i in rows:
            if i.mnemonic in ("fcomp","fcompp","fcom","fucom","fucomp","fucompp"):
                follow=rows[positions[i.address]+1:positions[i.address]+18]
                test=next((j for j in follow if j.mnemonic=="test" and j.op_str.startswith("ah,")),None)
                branch=next((j for j in follow if j.mnemonic.startswith("j")),None)
                assert test and branch and branch.mnemonic in ("je","jne"),(hx(i.address),test,branch)
                nonzero,zero={1:("less or unordered","ordered greater or equal"),0x40:("equal or unordered","ordered unequal"),0x41:("less, equal or unordered","ordered greater")}[test.operands[1].imm]
                comparisons.append(dict(site=hx(i.address),operand=i.op_str,test=hx(test.address),mask=test.operands[1].imm,branch=hx(branch.address),target=hx(branch.operands[0].imm),relation=nonzero if branch.mnemonic=="jne" else zero))
        constants=set()
        for i in rows:
            if i.mnemonic.startswith("f"):
                for o in i.operands:
                    if o.type==CS_OP_MEM and not o.mem.base and not o.mem.index and 0x960000<=o.mem.disp<0x980000:constants.add((o.mem.disp,o.size))
        functions.append(dict(entry=hx(start),native_body_bytes=expected_bytes,admitted_body_bytes=sum(b-a for a,b in ranges),span_end_exclusive=hx(ranges[-1][1]),
            native_body_ranges=[[hx(a),hx(b)] for a,b in native_ranges],
            pe_only_switch_closure=dict(start="006f1639",end_exclusive="006f164e",sha256=digest(read(0x6f1639,21)),instruction_sites=[hx(i.address) for i in closure]) if closure else None,
            body_ranges=[dict(start=hx(a),end_exclusive=hx(b),file_offset=f"0x{offset(a,b-a):x}",sha256=digest(read(a,b-a))) for a,b in ranges],
            instruction_count=len(rows),branch_count=len(branches),call_count=len(calls),rng_site_count=len(rng),nonframe_store_count=len(state),
            native_exports={ext:manifest["files"][hx(start)+"."+ext]["sha256"] for ext in ("asm","c")},
            all_exported_instructions_match=True,branches=branches,switches=[dict(site=hx(s),**v) for s,v in switches.items()],
            verified_R16_incoming_calls=incoming,incoming_list_exhaustive=False,
            direct_calls=[dict(target=t,count=len(s),sites=s) for t,s in sorted(targets.items())],
            normal_stack_check=dict(all_instruction_joins_balanced=True,all_returns_restore_entry_esp=True,entry_stack_accesses=[list(x) for x in sorted(args_access)],call_site_columns=["site","esp_delta_before_call","inferred_callee_cleanup_bytes"],call_sites=sorted(call_depths),limitation="Normal callee cleanup inferred; helper contracts and exception paths not proved"),
            returns=[[hx(i.address),i.operands[0].imm if i.operands else 0] for i in rows if i.mnemonic=="ret"],
            nonframe_stores=[dict(site=hx(i.address),operation=i.mnemonic,destination=i.op_str.split(",")[0],width_bytes=i.operands[0].size,source=i.op_str.split(",",1)[1].strip() if "," in i.op_str else None) for i in state],
            explicit_memory_store_sites=[hx(i.address) for i in stores],rng_sites=rng,x87_comparisons=comparisons,
            cfg=dict(all_blocks_structurally_reachable=True,block_count=len(blocks),block_columns=["start","end_exclusive","successors"],blocks=[[hx(b),hx(v[-1].address+v[-1].size),[hx(s) for s in edges[b]]] for b,v in blocks.items()],cycles=[[hx(b) for b in c] for c in cycles],upper_direct_rng_calls=upper,upper_limit="Structural maximum ignoring correlated predicates, with each signed-byte candidate scan bounded to127 iterations under normal callee preservation; excludes transitive RNG"),
            constants=[dict(address=hx(a),width_bytes=w,value=struct.unpack("<"+{4:"f",8:"d"}[w],read(a,w))[0],sha256=digest(read(a,w))) for a,w in sorted(constants)]))
    return dict(work_unit="R17-A",specimen_sha256=SHA,export_manifest_sha256=MANIFEST_SHA,annotation_preflight_sha256=PREFLIGHT_SHA,checkpoint_archive_sha256=manifest["checkpoint_archive_sha256"],evidence_class="complete local static instruction mapping; no execution oracle",decoder="Capstone 5.0.7 x86-32",address_kind="virtual; raw file offsets labelled",functions=functions,limits=["Calls may have unresolved transitive writes, RNG and failure behavior", "Structural CFG reachability does not prove runtime feasibility", "Float control and exceptional inputs unmeasured; no connected outcome claim"])

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("binary",type=Path);p.add_argument("--exports",type=Path,required=True);p.add_argument("--preflight",type=Path,required=True);p.add_argument("--output",type=Path,default=Path("evidence/match-dispatch-17-sites.json"))
    args=p.parse_args();args.output.write_text(compact(run(args))+"\n",encoding="utf-8",newline="\n");print(f"wrote {args.output}; static decoder check only")
