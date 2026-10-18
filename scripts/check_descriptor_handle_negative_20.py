#!/usr/bin/env python3
"""Reject altered oracle inputs and seven meaningful TS mutants in temporary files.

Run with the private Unicorn Python environment:
python check_descriptor_handle_negative_20.py NODE24 EXE NATIVE_ASM RECEIPT.json
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def require(condition, message):
    if not condition:
        raise ValueError(message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('node', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('native_asm', type=Path)
    parser.add_argument('receipt', type=Path)
    args = parser.parse_args()
    version = subprocess.check_output([str(args.node), '--version'], text=True).strip()
    require(int(version[1:].split('.')[0]) >= 24, 'requires Node24+')
    generator = ROOT/'scripts/emulate_descriptor_handle_20.py'
    checker = ROOT/'reconstruction/check-descriptor-handle.ts'
    implementation = ROOT/'reconstruction/descriptor-handle.ts'
    oracle = ROOT/'evidence/descriptor-handle-validation/oracle.json'
    rows = []
    with tempfile.TemporaryDirectory(prefix='descriptor-negative-20-') as directory:
        temp = Path(directory)
        wrong_binary = temp/'wrong-specimen.bin'
        wrong_binary.write_bytes(b'synthetic wrong specimen; not executable data')
        wrong_asm = temp/'changed-native.txt'
        wrong_asm.write_text('synthetic altered native input\n')
        for optimized in (False, True):
            for label, binary, assembly, expected in (
                ('wrong-specimen', wrong_binary, args.native_asm, 'unexpected specimen SHA-256'),
                ('changed-native', args.binary, wrong_asm, 'unexpected native assembly SHA-256')):
                output = temp/f'{label}-{optimized}'
                command = [sys.executable] + (['-O'] if optimized else []) + [str(generator), str(binary), str(assembly), str(output)]
                result = subprocess.run(command, capture_output=True, text=True)
                require(result.returncode != 0 and expected in result.stderr, f'{label} was not rejected')
                require(not output.exists(), f'{label} created output')
                rows.append({'case': label, 'python_optimized': optimized, 'rejected': True, 'output_written': False})
        (temp/'check-descriptor-handle.ts').write_bytes(checker.read_bytes())
        source = implementation.read_text()
        mutations = [
            ('bound-equality-accepted', 'descriptor >= memory.read32', 'descriptor > memory.read32'),
            ('any-flag-bit-open', '& 1) === 0', '& 255) === 0'),
            ('logical-page-shift', '(descriptor >> 5)', '(descriptor >>> 5)'),
            ('wrong-entry-stride', '(descriptor & 31) * 8', '(descriptor & 31) * 4'),
            ('stored-minus-one-fails', 'return memory.read32(entry);',
             'const handle = memory.read32(entry); return handle === 0xffffffff ? fail() : handle;'),
            ('failure-keeps-doserrno', 'memory.write32(0x00de2f90, 0);',
             'memory.write32(0x00de2f90, memory.read32(0x00de2f90));'),
            ('failure-write-order', 'memory.write32(0x00de2f90, 0);\n    memory.write32(0x00de2f8c, 9);',
             'memory.write32(0x00de2f8c, 9);\n    memory.write32(0x00de2f90, 0);'),
        ]
        for label, old, new in mutations:
            require(source.count(old) == 1, f'{label}: mutation site changed')
            (temp/'descriptor-handle.ts').write_text(source.replace(old, new), encoding='utf-8')
            output = temp/f'{label}.json'
            result = subprocess.run([str(args.node), str(temp/'check-descriptor-handle.ts'), str(oracle), str(output)], capture_output=True, text=True)
            require(result.returncode != 0 and 'AssertionError' in result.stderr, f'{label}: checker did not reject behavior')
            require(not output.exists(), f'{label}: wrote passing result')
            rows.append({'case': label, 'rejected': True, 'output_written': False})
    receipt = {'status': 'passed', 'node': version, 'python': platform.python_version(),
               'oracle_sha256': hashlib.sha256(oracle.read_bytes()).hexdigest(),
               'checks': rows, 'scope': 'synthetic negative inputs/mutants; no original data retained'}
    args.receipt.write_text(json.dumps(receipt, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'status': 'passed', 'negative_checks': len(rows)}))

if __name__ == '__main__':
    main()
