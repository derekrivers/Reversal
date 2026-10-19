#!/usr/bin/env python3
"""R33-B: original interior fixture producers followed by original placement entry."""
import argparse
import json
from pathlib import Path
import capstone
import extract_action33_slot_32 as slot
import extract_action33_lifecycle_31 as life

BASELINE='afbdea6fb05957f11fbfa83dbe852cc85f656cf9'
OWNER_MANIFEST='42425fa15eeb2da209497e396b81bacc99e77a2c608500cdd9febd7ee9091f79'
DB_MANIFEST='83d24d0790139ab37f7e3c82e12dfff9844456a8273e8d5ee10d1036359c7daf'
OWNER_RANGES={
 0x84c266:(0x84c2b1,0x84be20),0x84c3dd:(0x84c3ed,0x84be20),
 0x6b7f20:(0x6b7fb7,0x6b7f20),0x6b9787:(0x6b97a0,0x6b7f20),
 0x6b4ae2:(0x6b4af7,0x6b4360),0x6b53b0:(0x6b53bf,0x6b5260),
 0x6b5c92:(0x6b5cac,0x6b5a70),0x6b6b68:(0x6b6b76,0x6b6970),
 0x84c478:(0x84c498,0x84be20),0x84c4e3:(0x84c4fc,0x84be20)}
DB_RANGES={0x528b61:(0x528b8c,0x528540),0x529de9:(0x529e01,0x528540),
           0x528080:(0x528088,0x528080),0x5281e0:(0x52820a,0x528080)}
FRAME=0x304000
FIXTURE=FRAME+0x40
CLUBS=0x2a0000
SCOPE='synthetic interior producer windows and separate initializer/lookup/placement entries; no connected enclosing caller or live lifecycle'


def exports(folder,pinned,archive_key,archive):
    raw=(folder/'manifest.json').read_bytes();life.need(life.sha(raw)==pinned,'owner manifest mismatch')
    manifest=json.loads(raw)
    life.need(manifest['specimen_sha256']==life.SPECIMEN and manifest[archive_key]==archive,'owner archive provenance mismatch')
    native={}
    for name,meta in manifest['files'].items():
        data=(folder/name).read_bytes()
        life.need(len(data)==meta['bytes'] and life.sha(data)==meta['sha256'],'owner export mismatch '+name)
        if name.endswith('.asm'): native[int(name[:-4],16)]=life.rows(data)
    return native,{name:meta['sha256'] for name,meta in manifest['files'].items()}


def extract(a):
    pe,decoded,native,sites=slot.extract(a)
    owner,owner_hashes=exports(a.owner,OWNER_MANIFEST,'source_checkpoint_archive_sha256',life.ARCHIVES['focused'])
    db,db_hashes=exports(a.database,DB_MANIFEST,'source_archive_sha256',life.ARCHIVES['state'])
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for inventory,source in ((OWNER_RANGES,owner),(DB_RANGES,db),({0x6eaea0:(0x6eafa5,0x6eaea0)},native)):
        for start,(end,parent) in inventory.items():
            size=end-start;off=life.offset(pe,start,size);body=pe[off:off+size];seq=list(md.disasm(body,start))
            life.need(sum(i.size for i in seq)==size,'incomplete owner range')
            for ins in seq:
                if ins.address==0x6b7f6c:
                    life.need(ins.mnemonic=='rep stosd' and ins.op_str=='dword ptr es:[edi], eax' and
                              source[parent][ins.address]=='STOSD.REP ES:EDI','PE/native REP operand mismatch')
                else: life.compare([ins],source[parent])
            decoded.update((i.address,i) for i in seq)
            life.RANGES[start]=size
            ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),'file_offset':life.hx(off),
                'bytes':size,'sha256':life.sha(body),'instructions':len(seq),'all_native_operands_match':True})
    refs=(a.owner/'006b7f20.refs').read_text()
    life.need(set(refs.splitlines())=={
        '006b4af2 UNCONDITIONAL_CALL caller=006b4360','006b5ca7 UNCONDITIONAL_CALL caller=006b5a70',
        '0084c3e8 UNCONDITIONAL_CALL caller=0084be20','006b53ba UNCONDITIONAL_CALL caller=006b5260',
        '006b6b71 UNCONDITIONAL_CALL caller=006b6970'},'owner caller refs changed')
    sites.update(unit='R33-B',baseline_commit=BASELINE,scope=SCOPE,
        owner_manifest_sha256=OWNER_MANIFEST,database_manifest_sha256=DB_MANIFEST,
        owner_export_hashes=owner_hashes,database_export_hashes=db_hashes)
    sites['ranges']=[r for r in sites['ranges'] if r['entry']!='006eaea0']+ranges
    image_base,sections=life.pe_sections(pe)
    section=next(s for s in sections if image_base+s[2]<=0xae1050<image_base+s[2]+s[1])
    life.need(0xae1050-image_base-section[2]>=section[3],'contract global unexpectedly raw backed')
    sites['zero_tail_globals']['00ae1050']={'loader_zero':True,'game_initializer_executed':False}
    life.DATA_REGIONS['club_records']=(CLUBS,0x5000)
    life.ARG_COUNTS[0x6b7f20]=4
    return pe,decoded,sites


def stack_changes(before,after,changes):
    expected=bytearray(before['stack']);base=life.DATA_REGIONS['stack'][0]
    for address,width,value in changes:
        expected[address-base:address-base+width]=value.to_bytes(width,'little')
    life.need(bytes(expected)==after['stack'],'producer complete stack mismatch')


def produce(pe,decoded):
    cases=[]
    for club in range(4):
        for index in range(20):
            m=life.Machine(pe,decoded,club);home_id=club;away_id=7+index
            home=CLUBS+0x245*home_id;away=CLUBS+0x245*away_id
            m.set32(0xae23b4,CLUBS);m.set32(FRAME+0x1fc,home_id);m.set32(FRAME+0x200,away_id)
            m.entry(0x84c266,0,[]);m.uc.reg_write(life.REGS['esp'],FRAME);m.uc.reg_write(life.REGS['edi'],FRAME+0x200)
            before,after,producer,events=m.run(0x84c266,0x84c2b1,set())
            life.expected_data(before,after,[])
            half=int.from_bytes(before['stack'][FRAME+0x8d-0x300000:FRAME+0x8f-0x300000],'little')&0xff00
            stack_changes(before,after,[(FRAME+0x4c,4,home_id),(FRAME+0x8d,2,half),
                (FRAME+0x50,4,away_id),(FIXTURE+0x1c,4,home),(FRAME-4,4,0),
                (FRAME-8,4,0xfffffffe),(FIXTURE+0x20,4,away)])
            life.need([m.word(FIXTURE+0x1c),m.word(FIXTURE+0x20)]==[home,away],'club pointer producer mismatch')
            writes=[e for e in events if e[1]=='write' and e[2] in (life.hx(FIXTURE+0x1c),life.hx(FIXTURE+0x20))]
            life.need(writes==[['0084c294','write',life.hx(FIXTURE+0x1c),4],
                              ['0084c2ad','write',life.hx(FIXTURE+0x20),4]],'club producer widths mismatch')
            producer.update(home_id=home_id,away_id=away_id,home_pointer=home,away_pointer=away,
                            fixture=FIXTURE,pointer_writes=writes,function_entry=False)
            # Resume a distinct original caller window. Earlier calls, allocation and
            # constructor are excluded. ESI is explicitly supplied synthetic storage.
            m.entry(0x84c3dd,0,[])
            for r,v in [('esp',FRAME),('esi',0x250000),('ebx',0)]:m.uc.reg_write(life.REGS[r],v)
            before,after,binding,events=m.run(0x84c3dd,0x6b7f54,{(0x84c3e8,0x6b7f20)})
            life.expected_data(before,after,[(0x250000+0x4792,4,FIXTURE),(0,4,FRAME-36)])
            life.need(binding['call_frames']==[{'site':'0084c3e8','target':'006b7f20','ecx':0x250000,
                       'arguments':[FIXTURE,1,0,0]}],'owner caller argument provenance mismatch')
            owner_write=[e for e in events if e[1]=='write' and e[2]==life.hx(0x250000+0x4792)]
            life.need(owner_write==[['006b7f4e','write','00254792',4]],'owner store width/source mismatch')
            binding.update(owner_pointer=m.word(0x254792),owner_write=owner_write[0],function_entry=False,
                           callee_entry_executed=True,function_returned=False)
            saved_fixture=bytes(m.uc.mem_read(FIXTURE,0x60))
            selected=0x280000+0x1be*index
            initial=m.entry(0x6eada0,selected,[])
            before,after,initializer,_=m.run(0x6eada0,life.STOP,set())
            life.expected_data(before,after,[(selected+n,width,value) for n,width,value in slot.INIT_CHANGES])
            final=m.registers();life.need(final['eax']==selected and final['esp']==life.SP+4,'initializer ABI mismatch')
            life.need(all(final[r]==initial[r] for r in ('ebx','esi','edi','ebp')),'initializer nonvolatile mismatch')
            initializer.update(receiver=selected,side_value=m.uc.mem_read(selected+0x27,1)[0],function_returned=True)
            staff_id=(club*11+index)%32;staff=0x230000+staff_id*0x6e;attribute=0x240000+staff_id*0x46
            cell=0x210000+0x91*club+2+4*index
            for address,value in ((0x200601,0x210000),(0x220000,club),(0x2200cf,0),
                (0xae2350,1),(0xae235c,32),(0xae2364,64),(0xae23bc,0x230000),
                (cell,staff_id),(staff,staff_id),(staff+0x61,attribute)):
                m.set32(address,value)
            m.uc.mem_write(attribute+0x45,bytes([40+club]))
            initial=m.entry(0x8968f0,0x200000,[0x220000,0xa5a50000|index,0])
            before,after,lookup,_=m.run(0x8968f0,life.STOP,life.LOOKUP_CALLS)
            final=m.registers();returned=final['eax'];life.expected_data(before,after,[])
            life.need(returned==staff and final['esp']==life.SP+16,'lookup ABI mismatch')
            life.need(all(final[r]==initial[r] for r in ('ebx','esi','edi','ebp')),'lookup nonvolatile mismatch')
            lookup.update(returned_record=returned,function_returned=True)
            m.set32(0x260023,0x280000);m.set32(0x260012,0x250000)
            m.uc.mem_write(0x260018,bytes([club]));extra=0x89abcd80|club
            m.entry(0x6e0d00,0x260000,[0xa5a50000|index,returned,extra])
            before,after,placement,events=m.run(0x6e0d00,0x6eafa0,{(0x6e0dde,0x6eaea0)})
            life.expected_data(before,after,[(selected+0x19e,4,0x250000),(selected+0x69,4,returned),
                (selected+0x6d,4,attribute),(selected,1,index),(selected+0x2e,1,extra&255),(selected+0x17,1,40+club)])
            life.need(placement['call_frames']==[{'site':'006e0dde','target':'006eaea0','ecx':selected,
                'arguments':[0x250000,returned,0x89abcd00|club,0xa5a50000|index,extra]}],'placement argument provenance mismatch')
            reads=[e for e in events if e[2] in ('00254792',life.hx(FIXTURE+0x1c),life.hx(FIXTURE+0x20))]
            life.need(reads==[['006eaf8f','read','00254792',4],['006eaf95','read',life.hx(FIXTURE+0x1c),4]],'placement owner alias read mismatch')
            final=m.registers();args=[m.word(final['esp']+4*k) for k in range(2)]
            life.need(args==[returned,home] and final['ecx']==0,'next contract call provenance mismatch')
            life.need(bytes(m.uc.mem_read(FIXTURE,0x60))==saved_fixture,'stack fixture lifetime overwritten')
            life.need(m.word(0x254792)==FIXTURE and m.uc.mem_read(selected+0x27,1)==b'\0','owner or initialized side lost')
            placement.update(slot=selected,staff_alias=m.word(selected+0x69),attribute_alias=m.word(selected+0x6d),
                owner_pointer=m.word(0x254792),owner_reads=reads,side_value=0,fixture_preserved=True,
                next_call={'site':'006eafa0','target':'004cf5f0','ecx':final['ecx'],'arguments':args,'executed':False},
                final_registers=final,function_returned=False)
            cases.append({'club_id':club,'index':index,'staff_id':staff_id,'producer':producer,'binding':binding,
                          'initializer':initializer,'lookup':lookup,'placement':placement})
    stages=('producer','binding','initializer','lookup','placement')
    return {'unit':'R33-B','specimen_sha256':life.SPECIMEN,'synthetic_only':True,'scope':SCOPE,
        'cases':cases,'coverage':{'interior_fixture_producers':80,'interior_caller_bindings':80,
        'initializer_returns':80,'lookup_returns':80,'placement_frontiers':80,
        'instruction_steps':sum(c[s]['instruction_steps'] for c in cases for s in stages)}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','state','staff','focused','support','exports25','slot','owner','database','output'):
        p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.write_bytes(life.pack(result))
    print(json.dumps(result['oracle']['coverage']))
