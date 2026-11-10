# CyberForge v1.8.6 — Edition Guide

CyberForge v1.8.6 ships three editions from one shared source core.

## AIO

The default full workbench. Includes Dev Studio, Engine & Plugin Manager, 28 language/toolchain profiles, Security Operations, malware research, reverse engineering, Linux security workspace, privacy web reader, AI Navigator, Multi-Agent, RAG, evidence vault and connector adapters.

## Dev Edition

Programming-first navigation:

- Dashboard / operations overview
- Dev Studio, project templates and file explorer
- Toolchains and IDE integrations
- Code & SAST, AI Diff Viewer, multi-file patch review
- General sandbox/task runner
- AI Navigator and Multi-Agent
- Engine & Plugin Manager (fixed engine catalog and reviewed ZIP plugin packages)
- Preferences and permission management

Security-only operations pages are hidden from navigation. Shared security APIs remain in the shared codebase but are not exposed as Dev Edition navigation workspaces.

## Cybersecurity Edition

Security-first navigation:

- Security Operations, cases, evidence and reports
- Network, malware triage, DFIR, memory/forensics
- Threat intelligence, CVE/SBOM and scanner assessment
- Reverse engineering, BlackArch inventory, AnonSurf and Firejail
- Privacy Network and Private Web Reader
- AI Navigator, Multi-Agent, local knowledge/RAG and AI patch review
- Dev Studio project manager remains available because selected local projects are used for authorized static security assessment
- Engine & Plugin Manager for Bandit, oletools, Volatility 3 and reviewed plugin packages

## Build / data isolation

The source archive's `edition.json` chooses which pages are navigated to. Set `CYBERFORGE_EDITION=aio|dev|security` to override explicitly in source mode. Native builds are produced by `build_desktop.py --platform windows|macos|linux --edition ...` on the matching host OS; the edition manifest is included in the frozen bundle.

Frozen user-data paths are separate:

- Windows AIO: `%LOCALAPPDATA%\CyberForgeAIO`
- Windows Dev: `%LOCALAPPDATA%\CyberForgeAIO-Dev`
- Windows Security: `%LOCALAPPDATA%\CyberForgeAIO-Security`

Source mode stores data in that extracted copy's `data/` directory. Keep a separate backup before upgrading or switching editions.

## Packages

The v1.8.6 release is distributed as a source/build-kit archive. Native builds are produced separately on the target OS:

- Windows: PyInstaller `onedir` folder with an `.exe` launcher.
- macOS: PyInstaller `.app` bundle.
- Linux: PyInstaller portable directory.

GitHub Actions is configured to build AIO, Dev and Security on all three operating systems. The source archive itself does not contain these binaries. All editions share the same source core and optional integration adapters. Edition manifests affect navigation, labels and frozen data paths; they do not auto-install external engines. The Engine Manager installs supported catalog entries only after user confirmation.
