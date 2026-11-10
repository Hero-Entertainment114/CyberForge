# CyberForge AIO v1.8.5 — Internationalization & Localization

## Overview

v1.8.5 adds a persisted localization layer for the application interface. Vietnamese is the default locale and English is supported as an alternative. The locale catalogs are separate JSON resources and are included in the native desktop build inputs.

## What's new

- Added a language selector in Preferences → Appearance & Personalization.
- Added validated `localization.locale` to the local preference profile.
- Existing profiles from v1.8.4 migrate to Vietnamese without losing appearance, editor, AI or permission settings.
- Locale selection survives restart and is preserved by profile export/import; reset restores Vietnamese.
- Added allowlisted `/api/i18n/vi` and `/api/i18n/en` endpoints. Unknown locales are not served.
- Added client-side translation for static text, safe presentation attributes and dynamically inserted UI components.
- Translation deliberately skips code, terminal commands, preformatted blocks, textareas, SVG and user-entered content.
- Added locale resources to PyInstaller build commands and frozen-bundle self-test validation.

## Translation coverage

The English catalog includes translations for all Vietnamese-language text nodes in the shipped static HTML. The Vietnamese catalog covers all long-form English text nodes in that interface, plus the main navigation, frequently used controls, input hints, Preferences, Dev Studio, Engine/Plugin Manager and many concise labels. The shipped catalogs contain 1,003 Vietnamese and 264 English entries. Canonical technical terms and identifiers remain unchanged.

This is a broad localization foundation, not a claim that every workflow-specific dynamic status string is translated. External tool output and provider-generated responses are not rewritten. Only Vietnamese and English are enabled. Japanese, Korean, Simplified Chinese, French, German and Spanish remain future locale packs and are intentionally not shown in the language selector yet.

## Compatibility

The preference schema remains version 1 and adds an optional `localization` group. Profiles that do not contain the group receive `{"locale":"vi"}` during validation. Existing preference keys and permission policies are unchanged.

## Verification

- 19 dedicated localization tests cover catalog validation, translation coverage, persistence, legacy profile migration, reset/import/export behavior, loopback endpoints and desktop resource bundling.
- Full regression suite: 390 tests passed across 20 modules.
- Python compilation and inline JavaScript syntax checks pass.
- Native desktop dry-run includes `locales/` for all three host platforms.
- Frozen-bundle self-test now checks both locale catalogs.
- Native binaries were not built in this environment; this remains a source release with native build kit.
