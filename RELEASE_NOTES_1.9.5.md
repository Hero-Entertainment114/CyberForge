# CyberForge AIO v1.9.5 Release Notes

## Windows / Docker Desktop acceptance

Read-only diagnostics now distinguish Docker CLI, daemon reachability, Linux-vs-Windows engine, context, WSL version/status/distributions, and Docker Desktop process visibility. A target-host PowerShell script (`tools/windows_docker_acceptance.ps1`) optionally builds the NetLab image and then runs a built-in probe in a temporary `--network none` container. It requires AF_PACKET `NET_RAW`, observes a generated loopback UDP packet, confirms no default route, and mounts no sample or host directory. This probe has not been run in the Linux build environment; it must be executed on the target Windows machine.

## Packet decoding

- Classic PCAP and PCAPNG (Enhanced, Simple and Obsolete Packet Blocks).
- PCAPNG interface timestamp resolution (decimal/binary `if_tsresol`) and `if_tsoffset`.
- Ethernet/VLAN/QinQ, RAW IP, BSD NULL, Linux SLL and SLL2.
- IPv4/IPv6 extension headers, TCP/UDP and ICMP type/code metadata.
- DNS query/response metadata over UDP and TCP, HTTP/1 request/response headers with an allowlist, visible TLS ClientHello/ServerHello/alerts, SNI, ALPN, supported versions, ciphers, extensions and JA3-like fingerprint.
- Bounded parsing: 2 MiB capture, 12,000 packet records, bounded flows/reassembly/events.
- No payload bytes, query values, Authorization values, cookies, body data, certificates or TLS application data are exported.

## Defensive Agent

The Agent builds an auditable multi-step plan without executing it. The user selects exact steps and approves the workflow. Dependencies must be selected, actions run in plan order, plans expire after 30 minutes and can be consumed once. Separate acknowledgements gate untrusted sample execution, the inert Docker smoke probe and online OSV metadata lookup. A failure halts subsequent steps and the response reports both attempted and not-attempted approved steps.

## User authority and safety boundary

The user controls the selected evidence, session, action set, local/online data route and approvals. The Agent intentionally does not expose arbitrary shell commands, arbitrary target scanning, silent external requests or unrestricted host-control instructions. This is not a limitation of the user's access to the UI; it is a safety boundary against prompt injection, untrusted samples and accidental host damage.

## Known limitations

- No live Docker Desktop/Windows acceptance result is claimed from this build environment.
- AF_PACKET loopback capture requires `NET_RAW`; if the smoke test fails, packet capture must be treated as unavailable.
- Docker containers share the Linux kernel. They are not a VM or formal malware detonation boundary.
- PID attribution is best-effort. TCP reassembly is directional and bounded.
- TLS is not decrypted. HTTP/2 and HTTP/3 encrypted application data are not decoded.
- The source ZIP does not include native Windows/macOS binaries.
