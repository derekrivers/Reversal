#!/usr/bin/env python3
"""R36-B: contract row allocation frontiers and exhaustive source-class gate."""
import argparse
import json
from pathlib import Path
import capstone
import unicorn
import extract_action33_lifecycle_31 as life
from extract_status_lookup_25 import normalized

BASELINE='d984a187df89656313a76db249e56b91735ed984'
MANIFEST12='12bcb7700e4982f1cc8d15786f27cc018db58fdba02de89b0e1eb81c10a6076c'
SCOPE='synthetic initializer/reserve entries stop before allocators; separate exhaustive interior source-eligibility windows; no row/index write or lookup return executed'
COUNTS=(0,1,2,31,64,255,0x3333333,0x80000000,0xffffffff)
FLAGS=(0,1,2,0x80000000,0xffffffff)
ELIGIBLE=(0,6,7,8,9,10,11,12,13,15)
NATIVE={0x4c7560:(0x4c7945,'contracts',0x4c7560),0x4c79a0:(0x4c7abe,'contracts',0x4c79a0),
 0x54a110:(0x54a125,'support',0x54a110),0x8297ca:(0x82980e,'state',0x828110),
 0x83036c:(0x8303c4,'state',0x82ff40),0x82854b:(0x828564,'state',0x828110)}
PE_ONLY={0x85e410:0x63,0x85e960:0x46,0x85f78a:0x15,
         0x85ea42:0x60,0x85eaf0:6}


def parser():
    p=argparse.ArgumentParser()
    for name in ('binary','contracts','support','state','output'):p.add_argument(name,type=Path)
    return p


def exports(folder,pin,filename):
    raw=(folder/filename).read_bytes();life.need(life.sha(raw)==pin,'manifest mismatch '+filename)
    manifest=json.loads(raw);life.need(manifest['specimen_sha256']==life.SPECIMEN,'manifest specimen mismatch')
    files=manifest['files'];files={m['name']:m for m in files} if isinstance(files,list) else files
    native={};hashes={}
    for name,meta in files.items():
        raw=(folder/name).read_bytes()
        life.need(len(raw)==meta['bytes'] and life.sha(raw)==meta['sha256'],'native export mismatch '+name)
        hashes[name]=life.sha(raw)
        if name.endswith('.asm'):native[int(name[:-4],16)]=life.rows(raw)
    return native,hashes


def extract(a):
    pe=a.binary.read_bytes();life.need(len(pe)==7192576 and life.sha(pe)==life.SPECIMEN,'pinned specimen mismatch')
    life.need(capstone.__version__=='5.0.7' and unicorn.__version__=='2.1.4','decoder/emulator version mismatch')
    native={};hashes={}
    for group,pin,filename in (('contracts',MANIFEST12,'EXPORT-MANIFEST.json'),
      ('support',life.MANIFESTS['support'],'manifest.json'),('state',life.MANIFESTS['state'],'manifest.json')):
        native[group],hashes[group]=exports(getattr(a,group),pin,filename)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    decoded={};ranges=[]
    for start,(end,group,parent) in NATIVE.items():
        size=end-start;off=life.offset(pe,start,size);raw=pe[off:off+size];seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==size,'incomplete native range')
        equivalent={address:('JB '+text[3:] if text.startswith('JC ') else text) for address,text in native[group][parent].items()}
        life.compare(seq,equivalent);decoded.update((i.address,i) for i in seq)
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),'file_offset':life.hx(off),'bytes':size,
          'sha256':life.sha(raw),'instructions':len(seq),'native_operands_match':True})
    for start,size in PE_ONLY.items():
        off=life.offset(pe,start,size);raw=pe[off:off+size];seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==size,'incomplete PE-only range')
        decoded.update((i.address,i) for i in seq)
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(start+size),'file_offset':life.hx(off),'bytes':size,
          'sha256':life.sha(raw),'instructions':len(seq),'native_operands_match':False})
    critical={0x4c759a:'mov dword ptr [ebx + 4], eax',0x4c75a4:'call 0x944e46',
      0x4c787a:'jl 0x4c78a7',0x4c788e:'mov dword ptr [edx + ecx], eax',
      0x4c789b:'mov dword ptr [ecx + edx], eax',0x4c78a2:'call 0x85e960',
      0x4c79e4:'mov dword ptr [esi + 4], eax',0x4c7a0c:'mov dword ptr [esi], eax',
      0x85e472:'ret',0x85f79c:'ret 8',0x85eaf3:'mov dword ptr [esi + 4], ecx'}
    for address,text in critical.items():
        i=decoded[address];life.need(normalized(i.mnemonic+' '+i.op_str)==normalized(text),'critical row site changed '+life.hx(address))
    for address in (0x4c788e,0x4c789b,0x85eaf3):life.need(decoded[address].operands[0].size==4,'row/index store width mismatch')
    return pe,decoded,{'unit':'R36-B','baseline_commit':BASELINE,'specimen_sha256':life.SPECIMEN,'scope':SCOPE,
      'manifest_sha256':{'contracts':MANIFEST12,'support':life.MANIFESTS['support'],'state':life.MANIFESTS['state']},
      'export_sha256':hashes,'selected_ranges':ranges,
      'row_publication_static':{'executed':False,'eligibility_context_offset':57,'eligibility_class_offset':61,
        'eligible_classes':list(ELIGIBLE),'reserve_call':'004c7873 -> 004c79a0','reserve_flag':1,
        'negative_result_skips_publication':True,'auxiliary_stride':79,'manager_row_stride':80,
        'auxiliary_index_store':'004c788e','row_source_id_store':'004c789b',
        'row_constructor_call':'004c78a2 -> 0085e960','row_constructor_arguments':['source','source+52 DWORD'],
        'first_row_constructor_date_dependency':'0085e9a1 -> 00549f70',
        'row_context_id_store':'0085eaf3 from DWORD[EBP]',
        'row_context_resolution':'0085ea42 source+39; 0085ea55 -> 00540a50 can replace EBP'},
      'lifetime_static':{'receiver_publish':'008297fc','initializer_call':'00829809 -> 004c7560',
        'row_growth_call':'004c79f1 -> 00945667','receiver_destroy':'00830378 -> 004c74f0',
        'receiver_free':'0083037e -> 00944c94','receiver_clear':'00830386',
        'auxiliary_free':'008303b6 -> 009452ca','auxiliary_clear':'008303be'},
      'connected_lookup':{'advanced':False,'stop':'004cf62b','row_returned':False}}


def stack_expected(before,after,changes):
    expected=bytearray(before['stack']);base=life.DATA_REGIONS['stack'][0]
    for address,width,value in changes:expected[address-base:address-base+width]=(value&((1<<(width*8))-1)).to_bytes(width,'little')
    life.need(bytes(expected)==after['stack'],'complete stack mismatch')


def produce(pe,decoded):
    life.RANGES.clear();life.RANGES.update({0x4c7560:997,0x4c79a0:286,0x85e410:0x63,0x54a110:21})
    life.ARG_COUNTS.update({0x85e410:0,0x54a110:0})
    initializer=[]
    for seed,count in enumerate(COUNTS):
        m=life.Machine(pe,decoded,seed);receiver=0x290000;m.set32(0xae2364,count)
        initial=m.entry(0x4c7560,receiver,[]);s=life.SP;temp=s-0x25c
        before,after,row,events=m.run(0x4c7560,0x4c75a4,{(0x4c7587,0x85e410),(0x85e431,0x54a110),(0x85e43f,0x54a110)})
        size=count*80&0xffffffff
        life.expected_data(before,after,[(0,4,s-12),(receiver+4,4,count)])
        changes=[(s-4,4,0),(s-8,4,0x956c71),(s-12,4,0x13579bdf),
          (s-0x2e4,4,initial['ebx']),(s-0x2e8,4,initial['esi']),(s-0x2ec,4,initial['edi']),
          (s-0x2f0,4,size),(s-0x2f4,4,0),(s-0x2f8,4,0x9629eb),(s-0x2fc,4,s-12),
          (s-0x300,4,temp),(s-0x304,4,receiver),(s-0x308,4,initial['esi']),(s-0x30c,4,0x85e444)]
        for offset in (0x25,0x2d):changes.extend([(temp+offset,2,40),(temp+offset+2,2,1972),(temp+offset+4,4,1)])
        changes.extend((temp+offset,width,value) for offset,width,value in ((4,4,0xffffffff),(0x4a,4,0xffffffff),
          (0x49,1,0),(0x3b,2,0),(0x4e,1,0),(0x40,4,0),(0x45,4,0),(8,4,0)))
        stack_expected(before,after,changes)
        life.need(row['call_frames']==[{'site':'004c7587','target':'0085e410','ecx':temp,'arguments':[]},
          {'site':'0085e431','target':'0054a110','ecx':temp+0x25,'arguments':[]},
          {'site':'0085e43f','target':'0054a110','ecx':temp+0x2d,'arguments':[]}],'initializer temporary ABI mismatch')
        final=m.registers();life.need(final['esp']==s-0x2f0 and m.word(final['esp'])==size and final['ebx']==receiver and final['esi']==0,'initializer allocation arguments mismatch')
        life.need(m.word(0xae2d0c)==m.word(0xae1050)==0,'invented global table/receiver')
        initializer.append({'count':count,'requested_bytes':size,'receiver':receiver,'temporary':temp,
          'allocator_executed':False,'function_returned':False,'frontier':row})
    reserve=[]
    for seed,flag in enumerate(FLAGS):
        m=life.Machine(pe,decoded,seed);receiver=0x260000;initial=m.entry(0x4c79a0,receiver,[flag])
        before,after,row,events=m.run(0x4c79a0,0x4c7a02,set())
        life.expected_data(before,after,[(receiver+4,4,200)])
        stack_expected(before,after,[(life.SP-0x204,4,initial['esi']),(life.SP-0x208,4,16000)])
        life.need([m.word(receiver+k) for k in (0,4,8)]==[0,200,0] and m.word(life.SP-0x208)==16000,'reserve allocation boundary mismatch')
        reserve.append({'flag':flag,'receiver':receiver,'base':0,'capacity':200,'count':0,'requested_bytes':16000,
          'allocator_executed':False,'function_returned':False,'frontier':row})
    eligibility=[]
    for context in (0,0x220000):
        for classification in range(256):
            m=life.Machine(pe,decoded,classification%4);source=0x230000
            m.set32(source+0x39,context);m.uc.mem_write(source+0x3d,bytes([classification]))
            m.entry(0x4c7832,0,[]);m.uc.reg_write(life.REGS['edi'],source)
            eligible=context!=0 and classification in ELIGIBLE;stop=0x4c786c if eligible else 0x4c7907
            before,after,row,events=m.run(0x4c7832,stop,set())
            life.need(before==after,'eligibility window changed memory')
            wanted=[['004c7832','read','00230039',4]]+([['004c783d','read','0023003d',1]] if context else [])
            life.need(events==wanted,'eligibility read order mismatch')
            eligibility.append({'context':context,'classification':classification,'eligible':eligible,
              'entry':row['entry'],'stop':row['stop'],'instruction_steps':row['instruction_steps'],
              'trace_sha256':row['trace_sha256'],'events_sha256':row['events_sha256'],
              'memory_sha256':life.sha(life.compact(row['before_memory_sha256'])),'memory_unchanged':True,
              'observed_reads':events,'reserve_executed':False,'row_index_written':False})
    return {'unit':'R36-B','specimen_sha256':life.SPECIMEN,'synthetic_only':True,'scope':SCOPE,
      'initializer_frontiers':initializer,'reserve_frontiers':reserve,'eligibility_windows':eligibility,
      'coverage':{'initializer_entries':len(initializer),'reserve_entries':len(reserve),'eligibility_windows':len(eligibility),
        'eligible':sum(c['eligible'] for c in eligibility),
        'instruction_steps':sum(c['frontier']['instruction_steps'] for c in initializer+reserve)+sum(c['instruction_steps'] for c in eligibility),
        'allocator_calls_executed':0,'row_index_writes_executed':0,'row_returns':0}}


def generate(a):
    pe,decoded,sites=extract(a);return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();value=generate(a);a.output.write_bytes(life.pack(value));print(json.dumps(value['oracle']['coverage']))
