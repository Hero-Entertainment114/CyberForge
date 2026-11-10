# Windows + Docker Desktop acceptance test (v1.9.5)

This release is a **source package**. The build environment did not have Docker Engine or Windows, so it cannot honestly claim a live Docker Desktop/Windows isolation test. Run this acceptance probe on the target Windows machine before enabling sample execution.

## Prerequisites

- Windows 10/11 with a supported Docker Desktop installation.
- Docker Desktop switched to **Linux containers**.
- Docker daemon running and `docker info` reachable.
- PowerShell 5.1 or PowerShell 7.
- For the WSL 2 backend, keep WSL and the kernel updated. Docker's WSL guidance recommends WSL 2.1.5 or newer; Enhanced Container Isolation has additional prerequisites and is optional. The Hyper-V backend is another Docker Desktop option.
- Do not enable host networking for this acceptance test. The probe explicitly uses `--network none`.

## Run from the extracted project root

Open PowerShell in the extracted `CyberForge_AIO_v1.9.5` directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\tools\windows_docker_acceptance.ps1 -BuildImage
```

`-BuildImage` downloads the base `python:3.12-alpine` image if required and builds the CyberForge NetLab image. It does not run a user sample. Subsequent checks can omit `-BuildImage`:

```powershell
.\tools\windows_docker_acceptance.ps1
```

The script creates `docker-windows-acceptance.json` in the project root. Expected fields include:

- `docker_daemon=true` and `linux_engine=true`
- `network_none=true`
- `raw_socket=true`
- `loopback_packet_seen=true`
- `default_route_absent=true`
- `sample_mounted=false`
- `result=passed`

If `NET_RAW` is denied, Docker Desktop/ECI policy or the active engine may be restricting packet sockets. Do not weaken host security or add broad capabilities blindly. The app should report PCAP capture as unavailable until the narrow loopback probe passes.

## What this test does and does not establish

It starts one temporary container from the CyberForge image with `--network none`, drops all capabilities except `NET_RAW`, makes the root filesystem read-only, applies PID/memory/CPU bounds, and runs a built-in Python probe. The probe emits a UDP datagram to its own loopback interface and confirms that an AF_PACKET socket observes at least one loopback frame and that `/proc/net/route` has no default route. No sample or host folder is mounted.

This is a capability smoke test, **not** a container escape test, malware detonation test, VM snapshot test, Windows host NIC capture test, or formal isolation certification. Docker containers share the Linux kernel. Use a separately managed VM with snapshots and a dedicated, isolated network for higher-risk samples. Windows host packet capture is a separate visibility plane; `pktmon` can export ETL captures to PCAPNG for offline decoding, but it does not replace the in-container loopback capture.
