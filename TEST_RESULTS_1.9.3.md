# CyberForge AIO v1.9.3 — Test Results

## Validation summary

- Release preflight: **0 errors / 0 warnings**, including Python compilation, locale JSON, unique HTML IDs and inline JavaScript syntax.
- `python cyberforge.py --self-test`: `CyberForge 1.9.3 bundle OK (aio)`.
- Unit suite: **522/522 tests passed across 28 modules**. Modules were executed independently in isolated subprocess groups; the aggregate invocation can exceed the build environment execution window.
- New v1.9.3 module: **17/17 tests passed** (`tests.test_v193_sandbox_ai`).

## v1.9.3 tests

- Free provider status never returns API key values.
- Provider/model validation rejects OpenRouter paid-model identifiers and non-allowlisted Gemini models.
- Remote AI requires explicit per-request consent before network call.
- API key formats for OpenAI-style, Groq, Google, GitHub, AWS and private-key material are included in heuristic redaction checks.
- Fixed HTTPS provider endpoints are verified; no arbitrary provider URL is accepted.
- Sample staging is bounded, base64-validated, read-only and SHA-256-bound.
- Invalid extension, oversize input, invalid duration and invalid session ID are rejected.
- Tampered sample hashes, symlinked sample/input paths and invalid report schemas are rejected.
- Docker run command is verified to use `--network none`, read-only root/sample mount, dropped capabilities, no-new-privileges and process/resource bounds.
- Runtime capability output explicitly discloses the shared Docker Linux-kernel boundary.

## Manual smoke test

Remote provider calls additionally require a separate per-request $0-account acknowledgement and a separate data-transfer consent. The bundled runner/emulator was launched directly in the build container with a harmless, locally authored Python fixture. That fixture sent one DNS query for `probe.invalid` to `127.0.0.1:53`, one HTTP GET to `127.0.0.1:80`, and one TLS ClientHello with SNI `probe.invalid` to `127.0.0.1:443`. The report recorded 1 DNS query, 1 HTTP request, 1 TLS ClientHello, and one new process. The HTTP query string was omitted, TLS was not decrypted, and the sample used no external destination.

## Not tested / not claimed

- Docker Engine was not installed in the build environment. Therefore the actual Docker image build/run command, `--network none` behavior as enforced by Docker, and the host-to-container bind mount were validated by unit tests and code inspection, not by an actual Docker runtime execution here.
- Native Windows Docker Desktop, Windows Sandbox and ETW behavior were not run in a Windows host during this release build.
- This is not a VM/hypervisor, not an EDR, not packet capture, not TLS interception and not a kernel-level malware detonation engine.
- Free provider live calls were not made because no user credentials are available. Provider rates, quotas, model access, data retention and privacy terms are external and may change.
