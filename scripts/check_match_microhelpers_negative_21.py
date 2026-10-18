#!/usr/bin/env python3
"""Integrity and behavioral mutation probes for R21-A. Private inputs stay local.

python check_match_microhelpers_negative_21.py EXE EXPORTS PREFLIGHT NODE24 OUTPUT.json
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import extract_match_microhelpers_21 as extractor

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args, output, expected_text=None):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    require(result.returncode != 0, 'negative case was accepted')
    require(not output.exists(), 'negative case wrote valid-looking output')
    if expected_text:
        require(expected_text in result.stdout+result.stderr, 'wrong rejection reason')

def probe_operand(specimen, exports, preflight, output):
    # Resealing the TEST-ONLY manifest lets this probe reach operand comparison;
    # ordinary CLI execution still requires the pinned native manifest digest.
    extractor.MANIFEST = sha(exports/'manifest.json')
    extractor.extract(specimen, exports, preflight)
    output.write_text('unexpected acceptance')

def checks(specimen, exports, preflight, node, output):
    root = Path(__file__).resolve().parents[1]
    results = root/'results'
    results.mkdir(exist_ok=True)
    receipt = []
    with tempfile.TemporaryDirectory(prefix='micro-negative-', dir=results) as name:
        temporary = Path(name).resolve()
        require(temporary.parent == results.resolve(), 'temporary folder escaped results')
        wrong = temporary/'wrong.exe'
        data = bytearray(specimen.read_bytes()); data[-1] ^= 1; wrong.write_bytes(data)
        changed = temporary/'exports'
        shutil.copytree(exports, changed)
        assembly = changed/'007160d0.asm'
        assembly.write_text(assembly.read_text().replace('0x2b', '0x2c'), encoding='utf-8', newline='\n')
        manifest = json.loads((changed/'manifest.json').read_text())
        manifest['files'][assembly.name] = {'bytes': assembly.stat().st_size, 'sha256': sha(assembly)}
        (changed/'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        for optimized in [False, True]:
            python = [sys.executable] + (['-O'] if optimized else [])
            for program in ['extract_match_microhelpers_21.py', 'emulate_match_microhelpers_21.py']:
                for label, binary, native, expected in [('wrong-specimen', wrong, exports, 'specimen hash mismatch'),
                                                       ('changed-manifest', specimen, changed, 'manifest hash mismatch')]:
                    destination = temporary/f'{program}-{label}-{optimized}'
                    run(python+[root/'scripts'/program, binary, native, preflight, destination], destination, expected)
                    receipt.append({'case': label, 'program': program, 'optimized': optimized, 'rejected': True, 'output_written': False})
            destination = temporary/f'operand-{optimized}.json'
            run(python+[Path(__file__), '--operand-probe', specimen, changed, preflight, destination], destination,
                'complete original/native comparison failed')
            receipt.append({'case': 'operand-only-with-test-manifest-resealed', 'optimized': optimized,
                            'rejected': True, 'output_written': False})
        for mutation in ['upper-eax-cleared', 'edx-preserved-on-add', 'flags-preserved-on-add', 'no-byte-wrap', 'wrong-byte-offset',
                         'wrong-write-width', 'reset-write-order', 'cached-reset-pointer']:
            destination = temporary/f'{mutation}.json'
            run([node, root/'reconstruction/check-match-microhelpers.ts', root/'evidence/match-microhelpers-validation',
                 destination, mutation], destination, 'AssertionError')
            receipt.append({'case': mutation, 'rejected': True, 'output_written': False})
        optimized_output = temporary/'optimized-extract.json'
        subprocess.run([sys.executable, '-O', root/'scripts/extract_match_microhelpers_21.py', specimen, exports,
                        preflight, optimized_output], check=True, capture_output=True)
        require(optimized_output.read_bytes() == (root/'evidence/match-microhelpers-21-instructions.json').read_bytes(),
                'optimized extractor output differs')
    output.write_text(json.dumps({'status': 'passed', 'checks': receipt, 'optimized_valid_extraction_identical': True,
                                 'scope': 'synthetic mutations; changed private inputs are temporary; no native bytes retained'}, indent=2)+'\n',
                      encoding='utf-8', newline='\n')
    print(f'{len(receipt)} negative probes rejected without outputs; optimized valid extraction identical')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--operand-probe':
        probe_operand(*(Path(a) for a in sys.argv[2:]))
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        for arg in ['specimen', 'exports', 'preflight', 'node', 'output']:
            parser.add_argument(arg, type=Path)
        args = parser.parse_args()
        checks(args.specimen, args.exports, args.preflight, args.node, args.output)
