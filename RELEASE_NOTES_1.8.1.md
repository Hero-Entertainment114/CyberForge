# CyberForge AIO v1.8.1

## Corrective maintenance release

- Corrected nested folder creation in Dev Studio.
- Kept file creation explicit: create the parent folder first, then create the file.
- AI-reviewed patch export now maps all supported languages to the correct file extension.
- Dev Edition navigation is reduced to Dev Studio, Toolchains, AI Navigator, Multi-Agent Team and Preferences.
- Added quick navigation anchors for Projects, Editor, and Diagnostics/Git inside Dev Studio.
- Updated version metadata and regression expectations to 1.8.1.

## Verification

- 306 regression tests passed across the 16 test suites.
- Python compilation passed.
- JavaScript syntax check passed.
- This is a source release. It does not include a prebuilt native Windows executable.
- Full UI localization and native desktop packaging remain follow-up work; the language selector is not claimed as complete in this release.
