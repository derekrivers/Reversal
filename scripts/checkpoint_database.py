#!/usr/bin/env python3
"""Create an independent Ghidra checkpoint and verify its restored file hashes.

Run 'stage' only after the live project has closed. Run the retained Ghidra
verification command against restore-test, then run 'finalize'.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil, stat, struct, zipfile

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'database-checkpoint'
RESTORED=ROOT/'restore-test'
ARCHIVE=ROOT/'cm0102-ghidra-database.zip'
EXPECTED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def write_json(p,obj): p.write_text(json.dumps(obj,indent=2)+'\n',encoding='utf-8',newline='\n')
def clear_readonly_and_retry(func,path,exc):
    if not isinstance(exc,PermissionError):raise exc
    os.chmod(path,stat.S_IREAD|stat.S_IWRITE|stat.S_IEXEC)
    func(path)
def remove_stage_tree(p):
    if p not in (STAGE,RESTORED) or p.resolve().parent!=ROOT.resolve():
        raise ValueError(f'Unsafe checkpoint staging directory: {p}')
    if p.exists():shutil.rmtree(p,onexc=clear_readonly_and_retry)
def files(base):
    return {str(p.relative_to(base)): {'bytes':p.stat().st_size,'sha256':digest(p)}
            for p in sorted(base.rglob('*')) if p.is_file()
            and not any(part.startswith('.') for part in p.relative_to(base).parts)
            and not (p.name.startswith('tmp') and p.name.endswith('.ps'))}
def archive():
    with zipfile.ZipFile(ARCHIVE,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(STAGE.rglob('*')):
            if p.is_file() and not any(part.startswith('.') for part in p.relative_to(STAGE).parts):
                z.write(p,'cm0102-ghidra-database/'+str(p.relative_to(STAGE)))

def stage():
    data=(ROOT/'downloads/cm0102.exe').read_bytes()
    assert hashlib.sha256(data).hexdigest()==EXPECTED
    for p in [STAGE,RESTORED]:remove_stage_tree(p)
    STAGE.mkdir(); RESTORED.mkdir()
    project=STAGE/'ghidra-project'
    project_source=Path(os.environ.get('CM0102_GHIDRA_PROJECT_SOURCE',str(ROOT/'ghidra-project')))
    shutil.copytree(project_source,project,ignore=shutil.ignore_patterns('*.lock','*.lock~','.*','tmp*.ps'))
    annotations=json.loads((ROOT/'evidence/progression-annotations.json').read_text())
    source=(ROOT/'scripts/CM0102AnnotateMatch.java').read_text()
    rows=re.findall(r'\{"([0-9a-f]{8})","(cm0102_[^"]+)"',source)
    names=dict(rows[:10]);labels=dict(rows[10:])
    names.update({row[0]:row[1] for row in annotations['annotations']})
    types={t['path']:t for t in annotations['partial_data_types']}
    comments_by_address={}
    for receipt_name in ['event-annotations.json','penalty-annotations.json','shot-resolution-annotations.json','keeper-response-annotations.json','keeper-entry-annotations.json','investigation-09-annotations.json','investigation-10-annotations.json','investigation-11-annotations.json','investigation-12-annotations.json','investigation-13-annotations.json','investigation-14-annotations.json','investigation-15-annotations.json','investigation-16-annotations.json','investigation-17-annotations.json','investigation-18-annotations.json','investigation-19-annotations.json']:
      event_receipt=ROOT/'evidence'/receipt_name
      if event_receipt.exists():
        event_annotations=json.loads(event_receipt.read_text())
        names.update({row[0]:(row[2] if receipt_name in ('investigation-12-annotations.json','investigation-13-annotations.json','investigation-14-annotations.json','investigation-15-annotations.json','investigation-16-annotations.json','investigation-17-annotations.json','investigation-18-annotations.json','investigation-19-annotations.json') else row[1])
                      for row in event_annotations['annotations']})
        labels.update(dict(event_annotations['global_labels']))
        types.update({t['path']:t for t in event_annotations['partial_data_types']})
        comments_by_address.update({a:{'address':a,'text':note} for a,note in event_annotations['code_comments']})
    comments=list(comments_by_address.values())
    r12=json.loads((ROOT/'evidence/investigation-12-annotations.json').read_text())
    r12_names={row[0] for row in r12['annotations']}
    r12_notes={row[0]:'CM0102 investigation12 (2026-10-18): '+row[1] for row in r12['function_comments']}
    r13=json.loads((ROOT/'evidence/investigation-13-annotations.json').read_text())
    r13_names={row[0] for row in r13['annotations']}
    r13_notes={row[0]:'CM0102 investigation13 (2026-10-18): '+row[1] for row in r13['function_comments']}
    r14=json.loads((ROOT/'evidence/investigation-14-annotations.json').read_text())
    r14_names={row[0] for row in r14['annotations']}
    r14_notes={row[0]:'CM0102 investigation14 (2026-10-18): '+row[1] for row in r14['function_comments']}
    r15=json.loads((ROOT/'evidence/investigation-15-annotations.json').read_text())
    r15_names={row[0] for row in r15['annotations']}
    r15_notes={row[0]:'CM0102 investigation15 (2026-10-18): '+row[1] for row in r15['function_comments']}
    r16=json.loads((ROOT/'evidence/investigation-16-annotations.json').read_text())
    r16_names={row[0] for row in r16['annotations']}
    r16_notes={row[0]:'CM0102 investigation16 (2026-10-18): '+row[1] for row in r16['function_comments']}
    r17=json.loads((ROOT/'evidence/investigation-17-annotations.json').read_text())
    r17_names={row[0] for row in r17['annotations']}
    r17_notes={row[0]:'CM0102 investigation17 (2026-10-18): '+row[1] for row in r17['function_comments']}
    r18=json.loads((ROOT/'evidence/investigation-18-annotations.json').read_text())
    r18_names={row[0] for row in r18['annotations']}
    r18_notes={row[0]:'CM0102 investigation18 (2026-10-18): '+row[1] for row in r18['function_comments']}
    r19=json.loads((ROOT/'evidence/investigation-19-annotations.json').read_text())
    r19_names={row[0] for row in r19['annotations']}
    r19_notes={row[0]:'CM0102 investigation19 (2026-10-18): '+row[1] for row in r19['function_comments']}
    functions=[]
    for a,n in sorted(names.items()):
      row={'address':a,'name':n}
      if a in ['006b98c0','006bd930']:row['return_bytes']=1
      elif a=='006c38c0':row['return_bytes']=2
      if a in r12_names:row['comment']=r12_notes.get(a)
      if a in r13_names:row['comment']=r13_notes.get(a)
      if a in r14_names:row['comment']=r14_notes.get(a)
      if a in r15_names:row['comment']=r15_notes.get(a)
      if a in r16_names:row['comment']=r16_notes.get(a)
      if a in r17_names:row['comment']=r17_notes.get(a)
      if a in r18_names:row['comment']=r18_notes.get(a)
      if a in r19_names:row['comment']=r19_notes.get(a)
      functions.append(row)
    pe=struct.unpack_from('<I',data,0x3c)[0];optional=pe+24
    base=struct.unpack_from('<I',data,optional+28)[0]
    count=struct.unpack_from('<H',data,pe+6)[0];size=struct.unpack_from('<H',data,pe+20)[0]
    sections=[struct.unpack_from('<IIII',data,optional+size+40*i+8) for i in range(count)]
    signatures=[]
    for a in list(names)+['006d70c4']+[c['address'] for c in comments]:
        rva=int(a,16)-base
        for virtual,start,length,raw in sections:
            if start<=rva<start+length:
                signatures.append({'address':a,'hex':data[raw+rva-start:raw+rva-start+16].hex()});break
        else:raise ValueError(a)
    body_sites=[{'function':'006f09f0','address':address} for address in ('006f1639','006f163e','006f1640','006f1645','006f1647','006f164c')]
    expected={'sha256':EXPECTED,'functions':functions,'function_body_sites':body_sites,
              'labels':[{'address':a,'name':n} for a,n in sorted(labels.items())],
              'partial_data_types':list(types.values()),'code_signatures':signatures,'code_comments':comments}
    assert len(functions)>=14 and len(labels)>=5
    write_json(STAGE/'expected-database.json',expected)
    write_json(STAGE/'DB-MANIFEST.json',{'date_utc':'2026-10-18','ghidra':'12.1.4','jdk':'21',
        'input_sha256':EXPECTED,'project_files':files(project),
        'scope':'Native Ghidra project, function comments/names, RNG/event labels and recovered structures. Original executable bytes were not patched.',
        'expected_counts':{'functions':len(functions),'global_labels':len(labels),'structures':len(types),'fields':sum(len(t['fields']) for t in types.values()),'code_samples':len(signatures),'code_comments':len(comments),'function_body_sites':len(body_sites)},
        'limitations':'Research types are partial; no full game or match reproduction.'})
    (STAGE/'RESTORE.txt').write_text('''CM 01/02 3.9.68 — Ghidra database checkpoint

Unzip the complete archive to a writable directory. Keep cm0102.gpr and
cm0102.rep together inside ghidra-project. Open cm0102.gpr in Ghidra 12.1.4
(JDK 21), then open cm0102.exe in the project. Do not reimport the executable
or create a new project: the database already contains the imported image.

The original SHA-256 is recorded in DB-MANIFEST.json. Every saved project
file has a SHA-256 and byte count. expected-database.json specifies the
working function names, global labels, recovered structures and code samples.
The structure names and candidate fields are research annotations, not
recovered original C++ declarations. Types are saved in /CM0102/Recovered.

The final archive includes RESTORE-VERIFICATION.json from reopening an
independent extracted copy read-only without reanalysis. The complete
archive retains scripts/CM0102VerifyCheckpoint.java for repeating that test:

Set JAVA_HOME to JDK 21. Use Ghidra's support/analyzeHeadless executable:
  analyzeHeadless /absolute/unzipped/ghidra-project cm0102 \\
    -process cm0102.exe -noanalysis -readOnly \\
    -scriptPath /absolute/unzipped/scripts \\
    -postScript CM0102VerifyCheckpoint.java \\
    /absolute/unzipped/expected-database.json /new/verification.json

The complete research bundle additionally retains checkpoint_database.py.
''',encoding='utf-8',newline='\n')
    (STAGE/'scripts').mkdir()
    shutil.copyfile(ROOT/'scripts/CM0102VerifyCheckpoint.java',STAGE/'scripts/CM0102VerifyCheckpoint.java')
    archive()
    with zipfile.ZipFile(ARCHIVE) as z:z.extractall(RESTORED)
    restored=RESTORED/'cm0102-ghidra-database'
    assert files(restored/'ghidra-project')==files(project)
    print(json.dumps({'archive':str(ARCHIVE),'restore_directory':str(restored),'project_files':len(files(project))}))

def finalize():
    receipt=json.loads((ROOT/'evidence/database-restore-verification.json').read_text())
    manifest=json.loads((STAGE/'DB-MANIFEST.json').read_text())
    counts=manifest['expected_counts']
    assert receipt['status']=='passed' and receipt['partial_structures']==counts['structures'] and receipt['named_functions_and_comments']==counts['functions']
    assert receipt['global_labels']==counts['global_labels'] and receipt['structure_fields']==counts['fields']
    assert receipt['original_code_signatures']==counts['code_samples'] and receipt['code_comments']==counts['code_comments']
    assert receipt['function_body_sites_verified']==counts['function_body_sites']
    assert files(STAGE/'ghidra-project')==manifest['project_files']
    restored=RESTORED/'cm0102-ghidra-database/ghidra-project'
    actual={k:v for k,v in files(restored).items() if not k.endswith(('.lock','.lock~'))}
    assert actual==manifest['project_files'],'Restored project file content changed'
    receipt['project_file_hashes_verified']=len(actual)
    write_json(STAGE/'RESTORE-VERIFICATION.json',receipt)
    write_json(ROOT/'evidence/database-restore-verification.json',receipt)
    archive()
    with zipfile.ZipFile(ARCHIVE) as z:
        assert z.testzip() is None
        for name,spec in manifest['project_files'].items():
            b=z.read('cm0102-ghidra-database/ghidra-project/'+name.replace('\\','/'))
            assert len(b)==spec['bytes'] and hashlib.sha256(b).hexdigest()==spec['sha256']
    print(json.dumps({'status':'passed','archive':str(ARCHIVE),'bytes':ARCHIVE.stat().st_size,'sha256':digest(ARCHIVE),
                      'restored_checks':receipt},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['stage','finalize'])
    {'stage':stage,'finalize':finalize}[p.parse_args().action]()
