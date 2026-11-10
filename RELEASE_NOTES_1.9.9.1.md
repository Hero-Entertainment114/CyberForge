# CyberForge AIO v1.9.9.1 — Localization and Runtime Fix Pack

## Fixed

- Locale switching now keeps the original source text per DOM node and restores it when the newly selected language has no reviewed translation. This prevents text from the previously selected locale from remaining on screen.
- The same source-preserving behavior applies to `placeholder`, `title`, and `aria-label` attributes.
- MutationObserver updates are queued and batched. Attribute/text mutations caused by CyberForge's own translation pass are disconnected while applying changes, preventing self-triggered observer churn.
- Locale switching validates both the message catalog and a dedicated error catalog before applying it.
- The twelve locale catalogs now share an identical message-key set. This removes missing-key inconsistency; it does not mean every technical string has a human-reviewed translation.

## Localized application errors

- Added 24 normalized error codes covering unsupported locales, catalog load/validation, permissions, cancellation, missing items, invalid input, conflicts, timeout, network, storage, quota, missing dependencies, oversized files, unsafe archives, server failures, invalid responses, Docker availability, invalid paths and read-only resources.
- Permission confirmation prompts are translated and retain the dynamic capability/description placeholders.
- JSON API requests, binary uploads, and common GET requests now pass the selected locale and convert HTTP/network failures into localized application-level messages.
- Structured error/notice fields are localized when they match a known UI message or recognizable application-error class.
- Raw paths, stack traces, command output, source code, protocol names, OS error codes and third-party tool output remain verbatim so diagnostics are not corrupted.

## Translation scope and honest coverage

- English remains the default for new/reset profiles; existing valid locale selections are preserved.
- Twelve locale files are bundled: `en`, `vi`, `es`, `fr`, `de`, `pt`, `ja`, `ko`, `zh`, `ru`, `ar`, `hi`.
- This fix pack fully covers the normalized application error catalog in all twelve locales and improves common navigation/status strings. It does **not** claim that all 1,782 message strings have been human-reviewed in every language. `tools/i18n_check.py` reports actual authored message coverage by locale.
- A local-only completion tool, `tools/translate_catalogs.py`, can use an already-installed Ollama model to draft the remaining UI translations without sending app strings to a cloud service. Generated translations should be reviewed before release.

## Preserved behavior

- Existing API routes, workspaces, System Settings, Dev Studio, Security Workbench, sandbox and AI features are retained.
- English default, Arabic RTL, saved locale preservation and locale allowlist are retained.
- No new runtime dependency is required by the application.
