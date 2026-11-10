#!/usr/bin/env python3
"""Validate locale key parity and report actual translated-message coverage."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ('en','vi','es','fr','de','pt','ja','ko','zh','ru','ar','hi')

def main() -> int:
    catalogs = {}
    for code in LOCALES:
        path = ROOT / 'locales' / f'{code}.json'
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('locale') != code or not isinstance(data.get('messages'), dict):
            raise SystemExit(f'FAIL {code}: malformed catalog')
        if not isinstance(data.get('errors'), dict) or not isinstance(data['errors'].get('code'), dict):
            raise SystemExit(f'FAIL {code}: missing error catalog')
        catalogs[code] = data
    keysets = {code: set(data['messages']) for code, data in catalogs.items()}
    baseline = keysets['en']
    for code, keys in keysets.items():
        if keys != baseline:
            missing = sorted(baseline - keys)[:5]
            extra = sorted(keys - baseline)[:5]
            raise SystemExit(f'FAIL {code}: key parity mismatch missing={missing} extra={extra}')
    error_codes = set(catalogs['en']['errors']['code'])
    if len(error_codes) < 20:
        raise SystemExit('FAIL: error catalog is unexpectedly small')
    for code, data in catalogs.items():
        if set(data['errors']['code']) != error_codes:
            raise SystemExit(f'FAIL {code}: error code coverage mismatch')
        if any(not isinstance(v, str) or not v.strip() for v in data['errors']['code'].values()):
            raise SystemExit(f'FAIL {code}: empty error translation')
    print(f'PASS locales={len(catalogs)} shared_message_keys={len(baseline)} error_codes={len(error_codes)}')
    for code, data in catalogs.items():
        messages = data['messages']
        if code == 'en':
            translated = sum(messages[k] != k for k in baseline)
        else:
            en = catalogs['en']['messages']
            translated = sum(messages[k] != k and messages[k] != en.get(k, k) for k in baseline)
        pct = 100.0 * translated / max(1, len(baseline))
        print(f'{code}: authored_message_translations={translated}/{len(baseline)} ({pct:.1f}%) errors={len(data["errors"]["code"])}/{len(error_codes)}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
