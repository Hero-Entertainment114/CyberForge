# Contributing to CyberForge AIO

Thank you for considering a contribution.

## Before opening a change

- Keep changes focused and explain the user-facing impact.
- Do not commit API keys, passwords, private keys, local databases, logs, user projects, or runtime data.
- Preserve the existing permission checks and loopback-only service boundary.
- Do not represent optional integrations as available unless they are actually detected and tested.
- Include regression tests for bug fixes and feature changes.

## Local checks

Use Python 3.10 or newer. From the repository root:

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
python tools/release_check.py
```

Some platform-specific checks require Windows, macOS, Docker Desktop, or optional local tools. Report the host OS and exact commands used when a check cannot be run.

## Pull requests

Describe the problem, the approach, compatibility impact, tests run, and any new permissions or network access. Avoid bundling binaries or vendored third-party code unless its license and provenance are documented.
