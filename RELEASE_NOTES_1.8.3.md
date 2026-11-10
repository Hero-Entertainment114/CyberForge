# CyberForge v1.8.3 — Native Desktop Packaging

## Native desktop build pipeline
- Added a host-native PyInstaller builder for Windows, macOS and Linux.
- The builder refuses cross-platform targets instead of producing a host binary with the wrong platform label.
- Added OS-specific pywebview build environments: Windows / WebView2, macOS / Cocoa-WebKit, and Linux / Qt WebEngine.
- Added a post-package `--self-test` that checks the bundled UI, plugin directory and edition manifest from the frozen executable.
- Added a shared application icon in ICO, ICNS and PNG formats.
- Added a local process/resource monitor (PID, uptime, CPU time/average, thread count and memory RSS/peak) limited to the CyberForge process.
- Added a GitHub Actions matrix for all three editions on all three operating systems (nine platform/edition artifacts).
- Preserved the existing Windows batch/PowerShell entry points as wrappers around the shared desktop builder.

## Runtime and distribution notes
- Frozen app data remains in OS user-profile locations; it is not written beside the application bundle.
- Windows native mode requires the Microsoft Edge WebView2 Runtime and a compatible .NET runtime for pythonnet (prefer .NET 6+ Desktop Runtime; .NET Framework 4.6.2 is the fallback on supported architectures). The app falls back to the default browser if native startup fails.
- macOS uses the native Cocoa/WebKit backend; Linux uses the Qt WebEngine backend and requires compatible desktop libraries.
- Linux bundles are tied to the glibc compatibility baseline of their build runner.
- This source release does not include prebuilt EXE, APP, or Linux binaries. Builds must run on the corresponding target OS; see `BUILD_DESKTOP_LINUX.sh`, `BUILD_DESKTOP_MACOS.command`, and the Windows batch files.
- Code signing, macOS notarization, MSI/MSIX/PKG/DEB/RPM installers, automatic update and rollback are not included in this phase.

## Verification
- Added native builder regression tests and source-bundle self-test coverage.
- Python compilation, JavaScript syntax, builder dry-run and regression suites are recorded in `TEST_RESULTS.md`.
- Native build artifacts are not claimed as produced in this Linux container; the CI matrix is provided for target-host builds.
