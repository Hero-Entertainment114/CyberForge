#!/usr/bin/env python3
"""Run unittest modules in isolated processes and report exact test counts."""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TESTS=ROOT/'tests'

def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--timeout',type=float,default=90.0,help='Per-module timeout in seconds.')
    parser.add_argument('--module',action='append',default=[],help='Run only a named test module (repeatable).')
    args=parser.parse_args()
    modules=args.module or sorted(p.stem for p in TESTS.glob('test_*.py'))
    failures=[]; total=0; passed_modules=0
    for module in modules:
        if not (TESTS/f'{module}.py').is_file():
            print(f'FAIL {module}: module not found',flush=True); failures.append(module); continue
        print(f'== {module} ==',flush=True)
        try:
            result=subprocess.run([sys.executable,'-m','unittest',f'tests.{module}','-q'],
                                  cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                  text=True,check=False,timeout=args.timeout)
            output=result.stdout
            sys.stdout.write(output)
            match=re.search(r'Ran (\d+) tests?',output)
            count=int(match.group(1)) if match else 0
            if result.returncode==0 and 'OK' in output:
                total += count; passed_modules += 1
                print(f'PASS {module}: {count} tests',flush=True)
            else:
                failures.append(module)
                print(f'FAIL {module}: exit={result.returncode}, tests_seen={count}',flush=True)
        except subprocess.TimeoutExpired as exc:
            failures.append(module)
            print(f'TIMEOUT {module}: exceeded {args.timeout}s',flush=True)
            if exc.stdout:
                try: sys.stdout.write(exc.stdout.decode() if isinstance(exc.stdout,bytes) else exc.stdout)
                except Exception: pass
    print(f'TOTAL_TESTS={total} PASSED_MODULES={passed_modules}/{len(modules)} MODULE_FAILURES={len(failures)}',flush=True)
    if failures: print('FAILED_MODULES='+','.join(failures),flush=True)
    return 1 if failures else 0
if __name__=='__main__': raise SystemExit(main())
