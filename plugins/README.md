# CyberForge Engine & Plugin Manager (v1.8.4)

## Engine Manager

Engine Manager currently exposes a small, fixed catalog rather than accepting arbitrary package names:

| Engine | PyPI package | Pinned versions | Executable |
|---|---|---|---|
| Bandit | `bandit` | `1.9.4`, `1.9.3` | `bandit` |
| oletools | `oletools` | `0.60.2` | `olevba` |
| Volatility 3 | `volatility3` | `2.28.2`, `2.27.0` | `vol` |

Each version is installed into `data/engines/<engine-id>/<version>` using a dedicated Python virtual environment. The manager requires an external Python 3.10+ interpreter, selects an exact catalog version, uses binary wheels only and calls pip with an explicit PyPI index, no shell and a 15-minute timeout. It does not change system PATH or install system packages. Older installed versions stay available for switching/rollback. Removing the active version activates the most recently installed remaining version.

Pinned versions are reviewed catalog entries, not a cryptographic lock of every transitive dependency. The installed tools are third-party code and run as the current user. Review package metadata/provenance before using them on sensitive evidence. Installation contacts PyPI only after an explicit user action and the `engine_admin` Ask/Allow policy.

The catalog versions were checked against PyPI at the v1.8.4 release cut: Bandit 1.9.4, oletools 0.60.2 and Volatility 3 2.28.2. The catalog is intentionally narrow and must be updated by a reviewed source release; it does not execute arbitrary package IDs supplied by users.

## Plugin package format

A plugin is a ZIP with a flat root containing:

- `manifest.json` (required)
- one Python entrypoint named by `entrypoint` (required, direct `.py` file in the ZIP root)
- `README.md` (optional)

No nested folders, dependency manifests, install scripts, shared libraries or additional files are accepted. Package limits: 5 MiB archive, 8 MiB total uncompressed content, 80 entries; each file is limited to 2 MiB. The ZIP is checked for duplicate names, path traversal, symlinks, directories, encrypted entries and unsupported file types.

Example manifest:

```json
{
  "id": "example.indicator-enricher",
  "name": "Example Local Knowledge Enricher",
  "version": "1.0.0",
  "api_version": "1",
  "description": "A minimal offline example.",
  "runtime": "python:3.12-alpine",
  "entrypoint": "plugin.py",
  "capabilities": ["knowledge.read", "case.read", "threatintel.read"],
  "required_permissions": []
}
```

Only these capabilities are currently allowed: `knowledge.read`, `case.read`, `evidence.read`, `finding.write`, `scanner.static`, `threatintel.read`. `required_permissions` must be a subset of `capabilities`. Optional capabilities are available only when explicitly granted in the Permission Manager. Every install/update starts disabled and clears all previous grants. Review the new source before enabling it again.

The built-in sample source is `example-manifest.json` and `example.indicator-enricher/plugin.py`. A ready-to-import package is `packages/example.indicator-enricher-package-1.0.0.zip`.

## Plugin runtime and trust boundary

- Only `python:3.12-alpine` is accepted. Docker or Podman must already be installed and the image must already exist locally. CyberForge does not pull images.
- The container uses `--network none`, read-only root filesystem, read-only plugin mount, dropped Linux capabilities, no-new-privileges, a non-root UID, resource limits and a 35-second timeout.
- No host credentials, database file, arbitrary project directory or unrestricted host shell is mounted.
- Plugin input is a capability-filtered JSON context over stdin; output JSON is untrusted and is treated as a proposal, not silently committed data.
- Plugin installation stores files under the user's CyberForge data directory, but installed code is not loaded into the application process. It is launched only through the restricted container runner.
- The calculated SHA-256 is an integrity check against the hash supplied with the same package. It does not authenticate a publisher or replace a signed release / trusted distribution channel.

Plugin install, update and removal require the `plugin_admin` permission. Running a plugin additionally requires `plugin_execution` and a separate user acknowledgement. Permissions use Allow / Ask / Deny; Deny cannot be overridden by AI autonomy.
