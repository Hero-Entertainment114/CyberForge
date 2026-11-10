# CyberForge AIO v1.8.2

## Dev Studio workspace redesign

- Replaced the long, scroll-based Dev Studio page with four separate workspaces: Projects, Workspace, AI Assistant, and Diagnostics & Git.
- Reworked the editor layout into a two-column Explorer + Editor workspace. AI features now live in their own area.
- Added accessible workspace navigation with keyboard support and mobile-responsive layouts.
- Project search hits and diagnostics can jump back to the relevant editor line.
- Task Runner, Git, and multi-agent analysis now save dirty editor buffers before using project files.
- Save All keeps the active editor tab selected.
- Single-file AI patch application refuses to overwrite edits made after patch generation.

## Verification

- 7 new Dev Studio UI regression tests pass.
- All 20 Dev Studio backend tests in `test_v120` pass.
- All 12 Dev Studio regression tests in `test_v130` pass.
- Python compilation and JavaScript syntax checks pass.
- The full application remains a source release. No prebuilt Windows executable or complete browser visual test is included.
