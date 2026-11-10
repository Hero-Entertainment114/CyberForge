# CyberForge AIO v1.9.4 Test Results

## Unit coverage

- 29 test modules; **548/548 tests passed**, with every module run independently in an isolated subprocess. A single aggregate runner attempt exceeded the execution window after `test_v160`; no aggregate success is claimed.
- `tests/test_v194_telemetry_orchestration.py`: 26 new tests covering PCAP parsing, missing `NET_RAW`, flow-to-PID correlation, timeline de-duplication, SAST/dynamic correlation, Sigma templates, OSV consent and fixed endpoint, Qwen model/paid acknowledgement, checkpoints, staged rollback, PCAP artifact validation, same-session run comparison and API capability gates.
- `tests/test_v193_sandbox_ai.py`: 17 regression tests pass, including Qwen provider status and the idempotent Docker cleanup command.

## Static release gates

- `tools/release_check.py`: 0 errors / 0 warnings after final preflight.
- Python syntax compilation; inline JavaScript `node --check`; locale JSON and unique HTML IDs.
- `python cyberforge.py --self-test`: bundle check.
- Source ZIP integrity and SHA-256 checksum verification.

## Host-dependent tests not claimed

- The build host has no Docker Engine/CLI daemon; the actual NetLab Docker image build and container run were not executed.
- The build host denied `AF_PACKET` raw socket creation (`PermissionError`), so no genuine packet capture was produced here. Unit tests confirm bounded packet parsing and that capture fails closed when permission is missing.
- Windows Docker Desktop, Windows Sandbox guest and native Windows/macOS desktop builds were not executed by this Linux source build.

## Interpretation

Unit tests validate deterministic parsers, orchestration guards, artifact validation, API policy and mocked runtime paths. They do not certify container escape resistance, hypervisor isolation, kernel telemetry coverage, complete PID attribution, malware detection quality or a live host's Docker configuration.
