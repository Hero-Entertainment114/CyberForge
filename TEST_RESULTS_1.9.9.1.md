# CyberForge AIO v1.9.9.1 — Test Results

## Release result

- **661/661 tests passed across 36 test modules.**
- The 36 modules were executed independently in bounded groups. A single all-module runner invocation exceeded the outer execution window; it is not reported as one completed aggregate process. Modules that were cut at a group boundary were run individually and passed.
- **New v1.9.9.1 tests: 15/15 passed** (10 localization regression tests + 5 local translation-tool tests).
- **Release preflight: 0 failures, 0 warnings.**
- Python syntax compilation: **61 files**.
- Inline JavaScript: `node --check` passed.
- HTML IDs: **593 unique IDs**, no duplicates.
- All 12 locale JSON catalogs parse, have an identical **1,782-message key set**, and contain the same **24 localized application error codes**.
- `python cyberforge.py --self-test`: `CyberForge 1.9.9.1 bundle OK (aio)`.
- ZIP integrity and SHA-256 are verified after packaging.

## Test groups

The original v1.9.9 suite contained 646 tests across 34 modules. v1.9.9.1 adds two modules with 15 tests, bringing the total to 661 tests across 36 modules.

The regression run covered the original core, application, security, sandbox, telemetry, IDE, System Settings and v1.9.9 locale tests. The existing `test_v185_i18n` caught two missing version-banner keys after the patch version changed; those two keys were added to all locale catalogs and the module was rerun successfully (19/19).

## v1.9.9.1 localization coverage

`python tools/i18n_check.py` reports actual authored translations. Having the same key set in every catalog is not the same as having every string translated.

| Locale | Authored UI message translations | Error codes |
|---|---:|---:|
| English | 328 / 1,782 | 24 / 24 |
| Vietnamese | 1,201 / 1,782 | 24 / 24 |
| Spanish | 137 / 1,782 | 24 / 24 |
| French | 133 / 1,782 | 24 / 24 |
| German | 129 / 1,782 | 24 / 24 |
| Brazilian Portuguese | 137 / 1,782 | 24 / 24 |
| Japanese | 136 / 1,782 | 24 / 24 |
| Korean | 136 / 1,782 | 24 / 24 |
| Simplified Chinese | 136 / 1,782 | 24 / 24 |
| Russian | 138 / 1,782 | 24 / 24 |
| Arabic | 138 / 1,782 | 24 / 24 |
| Hindi | 136 / 1,782 | 24 / 24 |

The 24 common error messages and permission-confirmation prompts are authored for all 12 languages. Core navigation has some additional translations, but the advanced descriptive UI catalogs are **not yet 100% translated**. The checker deliberately excludes English fallback values when calculating coverage.

## Fixes verified

- Switching to a locale with a missing key restores the node's original source text instead of leaving the previous locale's translation behind.
- `placeholder`, `title` and `aria-label` attributes use the same restore-before-translate behavior.
- MutationObserver changes are queued and batched. CyberForge disconnects its own observer while applying translated changes to avoid self-triggering loops.
- Locale loading validates both `messages` and the `errors.code` catalog.
- JSON API requests, binary uploads and common GET requests convert HTTP and network failures into localized messages.
- Permission prompts use translated templates with preserved capability/description placeholders.
- Error display keeps technical detail such as exception classes, request IDs, paths and HTTP codes when useful; raw code, paths and third-party scanner output are not rewritten.
- The local translation completion tool accepts only loopback Ollama HTTP endpoints, preserves placeholders and is dry-run by default.

## Platform boundaries

- Build/test host: Linux, Python 3.13 and Node.js.
- Native Windows/macOS UI rendering and OS settings launch were not re-tested on those operating systems.
- No native EXE/APP installer was built in this source release.
- The local completion script drafts translations with an already-installed Ollama model. Generated translations are not included as reviewed translations until the user runs the script, reviews the output and reruns `tools/i18n_check.py`.
- Raw source code, terminal commands, protocol names, stack traces and third-party diagnostic output intentionally remain verbatim.
