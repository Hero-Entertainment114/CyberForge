# CyberForge AIO v1.9.2 — Test Results

## Complete regression result

**505 / 505 tests passed**

All 27 test modules completed successfully when run in isolated subprocess batches. The one-command aggregate invocation exceeded the local execution window while progressing through the suite; the modules were therefore grouped and rerun. No module is omitted from the table below.

| Test module | Passed |
|---|---:|
| `test_core` | 10 |
| `test_v011` | 11 |
| `test_v020` | 10 |
| `test_v040` | 23 |
| `test_v050` | 14 |
| `test_v060` | 9 |
| `test_v090` | 16 |
| `test_v100_ai` | 15 |
| `test_v111` | 26 |
| `test_v120` | 20 |
| `test_v130` | 12 |
| `test_v140` | 32 |
| `test_v150` | 22 |
| `test_v160` | 24 |
| `test_v170` | 33 |
| `test_v180` | 29 |
| `test_v182_ui` | 7 |
| `test_v183_desktop` | 21 |
| `test_v184_managers` | 37 |
| `test_v185_i18n` | 19 |
| `test_v186_integration` | 27 |
| `test_v187_workspace_search` | 4 |
| `test_v188_diagnostics` | 9 |
| `test_v189_onboarding_resources` | 9 |
| `test_v190_security_core` | 9 |
| `test_v191_defensive_workbench` | 24 |
| `test_v192_dynamic_sandbox` | 33 |
| **Total** | **505 across 27 modules** |

The legacy version assertions were updated to expect the current application version. The v1.9.1 module-specific feature tests continue to assert their own module result version where appropriate.

## New v1.9.2 test coverage

`tests/test_v192_dynamic_sandbox.py` adds 33 tests covering staging/validation, `.wsb` isolation settings, explicit launch acknowledgement, Windows-only launch guard, guest process/file/Registry/TCP/UDP/DNS collection markers, end-of-window process-tree termination, untrusted report schema/path/symlink/size checks, ETW CSV parser byte/row limits and heuristic domain/IP extraction, local Ollama loopback-only routing, rule-based fallback labeling and API permission wiring.

## Release preflight

Command:

```bash
python tools/release_check.py
```

Result: **0 failures, 0 warnings**. It checked app/edition/manifest/UI version consistency, release and validation notes, v1.9.1 and v1.9.2 module/route wiring, locales, 40 Python files, inline JavaScript syntax and **485 unique HTML IDs**.

Additional checks:

```bash
python cyberforge.py --self-test
python -m unittest tests.test_v192_dynamic_sandbox -q
```

Both passed; the dedicated v1.9.2 module reported 33 tests OK.

## Environment limitations

This build environment is Linux. It cannot start the Windows Sandbox guest, verify Windows edition/feature state, execute the PowerShell collector in Windows, or validate real ETW provider availability. The v1.9.2 guest runtime must be tested on an actual supported Windows host before relying on detonation evidence. No native Windows/macOS executable was produced in this source release.

The dynamic collector is best-effort and guest networking is disabled. It does not capture/decrypt packet payloads or prove successful external delivery. Absence of telemetry is not a benign verdict. Offline generative inference requires a separately available local Ollama runtime and model; the built-in rules fallback is not a generative LLM.
