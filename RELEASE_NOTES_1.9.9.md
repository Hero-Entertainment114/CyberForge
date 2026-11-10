# CyberForge AIO v1.9.9 Release Notes

## Modernized interface
- Complete refresh of the shared app shell and design tokens: more spacious layout, cleaner navigation, cohesive cards, controls, tables, statuses, improved responsive behavior, focus indicators and reduced-motion handling.
- Existing workspace IDs, API contracts and Dev Studio/Security Workbench functions are retained.
- Dark, light and system-following themes remain supported.

## Internationalization
- English is the default for new installations and reset profiles. Existing saved locale choices remain unchanged during upgrade.
- Twelve bundled languages: English, Vietnamese, Spanish, French, German, Brazilian Portuguese, Japanese, Korean, Simplified Chinese, Russian, Arabic (RTL) and Hindi.
- Core navigation, system settings and common controls are localized. Advanced diagnostics, engine output and some dynamic technical messages can remain in English.
- Catalog loading is allowlisted and bounded. Locale files are bundled; no translation network service is used.

## System Settings
- Application: language, theme, accent, density and sidebar layout.
- Device: bounded read-only OS/CPU/memory/disk/network overview and PATH presence checks for selected tools. It does not enumerate arbitrary processes or collect installed software inventories.
- OS settings handoff: fixed allowlisted Display/Network/Sound/Storage/Apps/Updates/Developer pages. Uses `host_app_launch` permission and the existing one-time confirmation flow; no arbitrary command or URI is accepted.
- Maintenance: links to health diagnostics and verified local SQLite backup features. Backups include the database only, not evidence blobs, project folders or service credentials.

## Boundaries
- Does not modify Windows Registry, OS preferences, drivers, power plans, firewall rules, routing or startup entries. Use the native OS settings panel for those changes.
- OS settings target availability varies by desktop environment and OS version. Linux GNOME/KDE launch is best effort.
- No native Windows/macOS binary was built in this source release.

## v1.9.9 usability fixes
- System database backup create/list/verify results are rendered in both the dashboard and System Settings maintenance panel.
- Language preview synchronizes both Preferences and System Settings selectors immediately.
- Removed a duplicate System Settings route title key.
- Added regression coverage for the cross-page result and locale synchronization.
