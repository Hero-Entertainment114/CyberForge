#!/usr/bin/env python3
"""Run release gates, create a clean source ZIP and write an external SHA-256."""
from __future__ import annotations
import argparse
import hashlib
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION=(ROOT/'VERSION.txt').read_text().strip()
EXCLUDED_PARTS={'.git','__pycache__','.pytest_cache','.mypy_cache','.venv','venv','data','dist','build'}

def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,default=ROOT.parent)
    parser.add_argument('--skip-tests',action='store_true',help='Skip unit tests; preflight still runs.')
    args=parser.parse_args(); args.output_dir.mkdir(parents=True,exist_ok=True)
    gates=[[sys.executable,str(ROOT/'tools'/'release_check.py')]]
    if not args.skip_tests: gates.append([sys.executable,str(ROOT/'tools'/'run_test_modules.py')])
    for command in gates:
        result=subprocess.run(command,cwd=ROOT,check=False)
        if result.returncode: raise SystemExit(f'Release gate failed: {command}')
    output=args.output_dir/f'CyberForge_AIO_v{VERSION}_source.zip'
    prefix=f'CyberForge_AIO_v{VERSION}/'
    files=[]
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.relative_to(ROOT).parts): continue
        if path.suffix in {'.pyc','.pyo','.log','.sqlite','.sqlite3','.db'}: continue
        if path == output: continue
        files.append(path)
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in files: archive.write(path,prefix+path.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(output,'r') as archive:
        bad=archive.testzip()
        if bad: raise SystemExit(f'ZIP integrity failure at {bad}')
    digest=hashlib.sha256(output.read_bytes()).hexdigest()
    checksum=output.with_suffix(output.suffix+'.sha256')
    checksum.write_text(f'{digest}  {output.name}\n',encoding='ascii')
    print(f'PACKAGE {output}\nFILES {len(files)}\nSHA256 {digest}\nZIP_INTEGRITY ok')
    return 0
if __name__=='__main__': raise SystemExit(main())
