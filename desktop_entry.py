"""Native desktop entry point shared by Windows, macOS, and Linux bundles."""
from __future__ import annotations

import os


def prepare_native_host() -> None:
    """Set stable Windows taskbar identity and DPI awareness when available."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("org.cyberforge.desktop")
        try:
            # PROCESS_PER_MONITOR_DPI_AWARE (2). Best-effort on older Windows builds.
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass
    except Exception:
        pass


def main() -> None:
    prepare_native_host()
    from cyberforge import main as run_application
    run_application()


if __name__ == "__main__":
    main()
