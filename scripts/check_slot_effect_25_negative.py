#!/usr/bin/env python3
"""Reject damaged inputs and deliberate reconstruction errors for R25-B."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def run(args):
    p = subprocess.run(args, capture_output=True, text=True)
    lines = (p.stderr or p.stdout).strip().splitlines()
    important = next((line for line in lines if line.startswith(('ValueError:', 'Error:'))),
                     lines[-1] if lines else '')
    return {"exit_code": p.returncode, "diagnostic": important[:240]}


def negative(args):
    script = Path(__file__).with_name('extract_slot_effect_25.py')
    checker = script.parent.parent/'reconstruction'/'check-slot-effect-severe.ts'
    baseline = [str(sys.executable),str(script),str(args.binary),'--exports',str(args.exports),
                '--preflight',str(args.preflight),'--output',str(args.output)]
    optimized = [str(sys.executable),'-O',*baseline[1:]]
    good = run(optimized)
    need(good['exit_code'] == 0, 'optimized valid extraction failed')
    results = {"optimized_valid":good}
    with tempfile.TemporaryDirectory(prefix='slot-effect-25-') as temp:
        temp = Path(temp)
        changed_pe = temp/'damaged.exe'
        shutil.copyfile(args.binary,changed_pe)
        with changed_pe.open('r+b') as handle:
            handle.seek(0x2d0a12)
            old = handle.read(1)
            handle.seek(0x2d0a12)
            handle.write(bytes([old[0]^1]))
        changed_cmd = optimized.copy()
        changed_cmd[3] = str(changed_pe)
        results['changed_pe_optimized'] = run(changed_cmd)
        need(results['changed_pe_optimized']['exit_code'] != 0
             and 'specimen size/SHA-256 mismatch' in results['changed_pe_optimized']['diagnostic'],
             'damaged specimen was accepted')
        export_copy = temp/'exports'
        export_copy.mkdir()
        for name in ('manifest.json','006d0980.asm','006d0980.c'):
            shutil.copyfile(args.exports/name,export_copy/name)
        asm = export_copy/'006d0980.asm'
        text = asm.read_text(encoding='utf-8')
        need('006d09f8  MOV dword ptr [ESI + 0x55],EAX' in text,
             'native mutation anchor changed')
        asm.write_text(text.replace('006d09f8  MOV dword ptr [ESI + 0x55],EAX',
                                    '006d09f8  MOV word ptr [ESI + 0x55],EAX'))
        changed_cmd = optimized.copy()
        changed_cmd[5] = str(export_copy)
        results['changed_native_width_optimized'] = run(changed_cmd)
        need(results['changed_native_width_optimized']['exit_code'] != 0
             and 'native export mismatch' in results['changed_native_width_optimized']['diagnostic'],
             'damaged native export was accepted')
        # Recompute the export hashes in a disposable copy and adjust only the
        # test script's manifest pin, so the operand-width gate is reached.
        manifest_path = export_copy/'manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        altered_asm = asm.read_bytes()
        manifest['files']['006d0980.asm']['bytes'] = len(altered_asm)
        manifest['files']['006d0980.asm']['sha256'] = hashlib.sha256(altered_asm).hexdigest()
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        old_manifest_sha = hashlib.sha256((args.exports/'manifest.json').read_bytes()).hexdigest()
        new_manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        test_script = temp/'extract_resealed.py'
        script_text = script.read_text(encoding='utf-8')
        need(old_manifest_sha in script_text, 'test script manifest pin changed')
        test_script.write_text(script_text.replace(old_manifest_sha,new_manifest_sha),encoding='utf-8')
        resealed_cmd = changed_cmd.copy()
        resealed_cmd[2] = str(test_script)
        results['resealed_native_width_optimized'] = run(resealed_cmd)
        need(results['resealed_native_width_optimized']['exit_code'] != 0
             and 'native/original operand width mismatch at 006d09f8' in
             results['resealed_native_width_optimized']['diagnostic'],
             'changed width escaped operand gate')
    for label, mutation in (('wrong_float_bits','--mutate-value'),('reordered_effects','--mutate-order')):
        row = run([str(args.node),str(checker),str(args.oracle),mutation])
        need(row['exit_code'] != 0 and 'original-entry effect mismatch' in row['diagnostic'],
             label+' reconstruction mutation survived')
        results[label] = row
    return {"work_unit":"R25-B","specimen_sha256":hashlib.sha256(args.binary.read_bytes()).hexdigest(),
            "tests":results}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--oracle',type=Path,required=True)
    p.add_argument('--node',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    a.output.write_text(json.dumps(negative(a),indent=2)+'\n',encoding='utf-8',newline='\n')
