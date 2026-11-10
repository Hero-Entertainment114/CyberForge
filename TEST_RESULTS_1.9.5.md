# CyberForge AIO v1.9.5 Test Results

## Results

- **581/581 tests passed across 30 unittest modules.** Each module was executed independently in a subprocess through `tools/run_test_modules.py` batches.
- The 10-module batch 1 passed 154 tests; the 10-module batch 2 had one initial localization failure (new v1.9.5 UI strings missing from Vietnamese catalog), then passed after adding translations; the final 10-module batch passed 191 tests.
- v1.9.5 runtime/packet/agent test module: **33/33 passed**.
- Release preflight: **0 errors, 0 warnings** (after report/manifest are generated and final preflight is rerun).
- Python compilation, JavaScript `node --check`, JSON locale/manifest parsing and HTML ID uniqueness validated by `tools/release_check.py`.
- `python cyberforge.py --self-test` must report `CyberForge 1.9.5 bundle OK (aio)`.

## v1.9.5-specific coverage

- Classic PCAP and PCAPNG Enhanced/Simple/Obsolete Packet Blocks.
- PCAPNG decimal timestamp resolution, Ethernet/VLAN, RAW IP, IPv4/IPv6, DNS/UDP/TCP, HTTP request/response privacy, split TCP streams, TLS ClientHello/ServerHello/alert metadata.
- AF_PACKET loopback normalization for raw-IP and synthetic Ethernet/VLAN headers.
- Docker Desktop diagnostics with mocked Windows/WSL/Linux-engine responses.
- Docker smoke test requires explicit acknowledgement, a pre-existing image, an actual loopback packet observation and no default route. Unit tests verify command arguments contain `--network none` and no host/sample bind mount.
- Defensive Agent plan is non-executing; exact allowlisted step IDs, dependencies, extra sample/network/Docker acknowledgements, one-shot plan status, dynamic capability mapping, secret/source redaction and reporting of approved-but-not-attempted steps.
- PowerShell acceptance script presence and intended controls are checked by unit tests.

## Host-specific verification not performed here

The build environment did **not** provide Windows, Docker Desktop, Docker Engine or the host privileges required to open AF_PACKET packet sockets. Therefore this release does not claim a live Docker Desktop/Windows integration test, a successful Docker image build/run on the target host, a genuine guest-loopback PCAP capture on Docker Desktop, or isolation certification.

Run the supplied script on the Windows target:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\tools\windows_docker_acceptance.ps1 -BuildImage
```

The probe runs one inert command in a temporary `--network none` container. It does not mount or execute a user sample. See `WINDOWS_DOCKER_ACCEPTANCE.md`.

## Known limits

- Docker containers share the Linux kernel; the NetLab container is not a VM or formal malware detonation boundary.
- `NET_RAW` availability depends on Docker Desktop engine configuration and host policy. If unavailable, PCAP is explicitly unavailable.
- PID attribution is best-effort; short-lived sockets can disappear before `/proc` inspection.
- TCP reassembly is bounded/directional and not a full TCP stack. Out-of-order capture and sequence wrap can limit application protocol decoding.
- TLS is not decrypted. HTTP/2/HTTP/3 encrypted application data is not decoded. No certificate bodies, HTTP body, query values, cookies or Authorization values are exported by the metadata decoder.
- The source ZIP does not include native Windows/macOS binaries.

## Module counts

| Module | Tests |
|---|---:|
| test_core | 10 |
| test_v011 | 11 |
| test_v020 | 10 |
| test_v040 | 23 |
| test_v050 | 14 |
| test_v060 | 9 |
| test_v090 | 16 |
| test_v100_ai | 15 |
| test_v111 | 26 |
| test_v120 | 20 |
| test_v130 | 12 |
| test_v140 | 32 |
| test_v150 | 22 |
| test_v160 | 24 |
| test_v170 | 33 |
| test_v180 | 29 |
| test_v182_ui | 7 |
| test_v183_desktop | 21 |
| test_v184_managers | 37 |
| test_v185_i18n | 19 |
| test_v186_integration | 27 |
| test_v187_workspace_search | 4 |
| test_v188_diagnostics | 9 |
| test_v189_onboarding_resources | 9 |
| test_v190_security_core | 9 |
| test_v191_defensive_workbench | 24 |
| test_v192_dynamic_sandbox | 33 |
| test_v193_sandbox_ai | 17 |
| test_v194_telemetry_orchestration | 26 |
| test_v195_runtime_packet_agent | 33 |
| **Total** | **581** |
