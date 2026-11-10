# CyberForge Internationalization v1.9.9.1

English (`en`) is the default language for fresh installations. Vietnamese remains fully supported. Ten additional locale catalogs are bundled: Spanish (`es`), French (`fr`), German (`de`), Brazilian Portuguese (`pt`), Japanese (`ja`), Korean (`ko`), Simplified Chinese (`zh`), Russian (`ru`), Arabic (`ar`) and Hindi (`hi`).

Core navigation, system settings and common actions are localized. Advanced diagnostic output, third-party tool output and some dynamically generated technical descriptions may remain in English when no translation exists. Arabic sets document direction to RTL. Locale catalogs are bundled JSON files from a fixed allowlist; arbitrary paths are never accepted.

Change the language in **System Settings → Application** or **Preferences & Autonomy**. Existing saved locale preferences are preserved during upgrade; English is used for new/default profiles.


## v1.9.9.1 localization fixes

Each catalog now has the same message keys and 24 normalized error codes. The browser remembers original text/attributes so locale switching restores the source before applying a new translation. If the current locale has no reviewed translation, it no longer leaves the previous locale's text in place.

Run `python tools/i18n_check.py` for actual authored translation coverage. To draft remaining UI strings with an already-installed local Ollama model, see `tools/translate_catalogs.py`. Only loopback Ollama endpoints are accepted; no cloud translation service is used. Review every generated string before release, especially security warnings and consent prompts.

Raw code, paths, stack traces, commands, protocol identifiers and third-party tool messages are intentionally preserved. Translating those fields can corrupt diagnostics.
