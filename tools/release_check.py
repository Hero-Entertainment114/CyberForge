#!/usr/bin/env python3
"""Fail-closed preflight checks for a CyberForge source release."""
from __future__ import annotations
import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class IDs(HTMLParser):
    def __init__(self):
        super().__init__(); self.values=[]; self.scripts=[]; self.in_script=False
    def handle_starttag(self, tag, attrs):
        vals=dict(attrs)
        if vals.get('id'): self.values.append(vals['id'])
        if tag.lower()=='script': self.in_script=True
    def handle_endtag(self, tag):
        if tag.lower()=='script': self.in_script=False
    def handle_data(self, data):
        if self.in_script and data.strip(): self.scripts.append(data)

def main() -> int:
    failures=[]; warnings=[]
    version=(ROOT/'VERSION.txt').read_text().strip()
    manifest=json.loads((ROOT/'RELEASE_MANIFEST.json').read_text())
    edition=json.loads((ROOT/'edition.json').read_text())
    source=(ROOT/'cyberforge.py').read_text()
    ui=(ROOT/'static/index.html').read_text()
    checks={
        'release_manifest_version': manifest.get('version')==version,
        'edition_version': edition.get('version')==version,
        'python_app_version': bool(re.search(rf'APP_VERSION\s*=\s*[\"\']{re.escape(version)}[\"\']',source)),
        'ui_version': f'v{version}' in ui,
        'release_notes_exist': (ROOT/str(manifest.get('release_notes',''))).is_file(),
        'validation_notes_exist': (ROOT/str(manifest.get('validation_notes',''))).is_file(),
        'diagnostics_module_exists': (ROOT/'runtime_diagnostics.py').is_file(),
        'v191_security_module_exists': (ROOT/'v191_modules.py').is_file(),
        'v191_security_tests_exist': (ROOT/'tests'/'test_v191_defensive_workbench.py').is_file(),
        'v191_api_namespace_wired': '/api/v191/' in source and 'v191_modules.' in source,
        'v192_dynamic_module_exists': (ROOT/'v192_modules.py').is_file(),
        'v192_tests_exist': (ROOT/'tests'/'test_v192_dynamic_sandbox.py').is_file(),
        'v192_api_namespace_wired': '/api/v192/' in source and 'v192_modules.' in source,
        'v192_sandbox_ui_wired': 'dynamicSandboxWorkbench' in ui and 'offlineLLMWorkbench' in ui,
        'v192_network_disabled_wsb': 'Networking' in (ROOT/'v192_modules.py').read_text() and 'Disable' in (ROOT/'v192_modules.py').read_text(),
        'v193_module_exists': (ROOT/'v193_modules.py').is_file(),
        'v193_tests_exist': (ROOT/'tests'/'test_v193_sandbox_ai.py').is_file(),
        'v193_api_namespace_wired': '/api/v193/' in source and 'v193_modules.' in source,
        'v193_loopback_netlab_wired': 'networkSimulationLab' in ui and '--network' in (ROOT/'v193_modules.py').read_text() and 'none' in (ROOT/'v193_modules.py').read_text(),
        'v193_runner_exists': (ROOT/'sandbox'/'netlab'/'netlab_runner.py').is_file(),
        'v193_dockerfile_exists': (ROOT/'sandbox'/'netlab'/'Dockerfile').is_file(),
        'v193_ai_provider_policy': 'openrouter/free' in (ROOT/'v193_modules.py').read_text() and 'gemini-3.1-flash-lite' in (ROOT/'v193_modules.py').read_text(),
        'v194_module_exists': (ROOT/'v194_modules.py').is_file(),
        'v194_tests_exist': (ROOT/'tests'/'test_v194_telemetry_orchestration.py').is_file(),
        'v194_api_namespace_wired': '/api/v194/' in source and 'v194_modules.' in source,
        'v194_pcap_collector_exists': (ROOT/'sandbox'/'netlab'/'netlab_telemetry.py').is_file(),
        'v195_netlab_image_versioned': 'cyberforge/netlab:1.9.5' in (ROOT/'v193_modules.py').read_text(),
        'v194_pid_flow_correlation': 'pcap_flow_observed' in (ROOT/'v194_modules.py').read_text(),
        'v194_qwen_paid_policy': 'qwen3.8-max' in (ROOT/'v193_modules.py').read_text() and 'PAID BY DEFAULT' in (ROOT/'v193_modules.py').read_text(),
        'v195_module_exists': (ROOT/'v195_modules.py').is_file(),
        'v195_tests_exist': (ROOT/'tests'/'test_v195_runtime_packet_agent.py').is_file(),
        'v195_api_namespace_wired': '/api/v195/' in source and 'v195_modules.' in source,
        'v195_ui_wired': 'v195Workbench' in ui and 'v195CreateAgentPlan' in ui,
        'v195_pcapng_packet_and_timestamp_support': 'block_type == 2' in (ROOT/'v195_modules.py').read_text() and 'ts_resolution' in (ROOT/'v195_modules.py').read_text(),
        'v195_windows_acceptance_script': (ROOT/'tools'/'windows_docker_acceptance.ps1').is_file(),
        'v195_windows_acceptance_docs': (ROOT/'WINDOWS_DOCKER_ACCEPTANCE.md').is_file(),
        'v195_smoke_probe_checks_packet_and_route': 'loopback_packet_seen' in (ROOT/'v195_modules.py').read_text() and 'default_route_absent' in (ROOT/'v195_modules.py').read_text(),
        'v195_agent_per_step_approval': 'granularity' in source and 'execute_only_selected_steps' in source,
        'v196_dev_ide_module_exists': (ROOT/'v196_modules.py').is_file(),
        'v196_dev_ide_tests_exist': (ROOT/'tests'/'test_v196_dev_ide.py').is_file(),
        'v196_ide_capabilities_api': '/api/dev/ide/capabilities' in source and 'v198_modules.ide_capabilities(' in source,
        'v196_terminal_api_routes': all(x in source for x in ('/api/dev/terminal/open','/api/dev/terminal/input','/api/dev/terminal/interrupt','/api/dev/terminal/close')),
        'v196_terminal_permission_gated': '"/api/dev/terminal/input": ["code_execution"]' in source,
        'v196_monaco_pinned_loader': 'monaco-editor@0.57.0' in ui and '/static/vendor/monaco/min/vs' in ui,
        'v196_monaco_vendor_tool': (ROOT/'tools'/'vendor_monaco.py').is_file(),
        'v196_explorer_operations': 'devExplorerSelectedPath' in ui and 'function renderDevTree(items)' in ui and 'function deleteDevCurrent()' in ui,
        'v196_command_palette_and_quick_open': 'function openDevCommandPalette' in ui and 'function openDevQuickOpen' in ui,
        'v196_terminal_interrupt_ui': 'function interruptDevTerminal()' in ui and 'id="devTerminalInput"' in ui,
        'v197_protocol_module_exists': (ROOT/'v197_modules.py').is_file(),
        'v197_protocol_tests_exist': (ROOT/'tests'/'test_v197_ide_protocols.py').is_file(),
        'v197_lsp_dap_api_routes': all(x in source for x in ('/api/dev/lsp/start','/api/dev/lsp/request','/api/dev/debugger/start','/api/dev/debugger/command')),
        'v197_protocol_capabilities_api': '/api/dev/ide/protocols' in source and 'v198_modules.ide_capabilities(' in source,
        'v197_monaco_lsp_providers': all(x in ui for x in ('registerCompletionItemProvider','registerHoverProvider','registerDefinitionProvider','registerSignatureHelpProvider')),
        'v197_git_source_control': all(x in source for x in ('staged-diff','branch-create','branch-switch','identity')) and 'id="devGitSourceControl"' in ui,
        'v197_no_arbitrary_vscode_extension_host': 'vscode_vsix_execution' in (ROOT/'v197_modules.py').read_text() and 'vscode_vsix_execution": False' in (ROOT/'v197_modules.py').read_text(),
        'v198_module_exists': (ROOT/'v198_modules.py').is_file(),
        'v198_tests_exist': (ROOT/'tests'/'test_v198_extensions_pty_multi_dap.py').is_file(),
        'v198_ide_capabilities_wired': '/api/dev/ide/capabilities' in source and 'v198_modules.ide_capabilities(' in source,
        'v198_extension_manager_routes': all(x in source for x in ('/api/dev/extensions/install','/api/dev/extensions/state','/api/dev/extensions/uninstall')),
        'v198_declarative_extension_policy': 'declarative-only' in (ROOT/'v198_modules.py').read_text() and 'activationEvents' in (ROOT/'v198_modules.py').read_text() and 'executable_code_loaded\": False' in (ROOT/'v198_modules.py').read_text(),
        'v198_multi_language_dap': all(x in (ROOT/'v198_modules.py').read_text() for x in ('cpp-lldb','dotnet-netcoredbg','python-debugpy')),
        'v198_pty_terminal_manager': all(x in (ROOT/'v198_modules.py').read_text() for x in ('posix-pty','pywinpty-conpty','PtyProcess.spawn','pty.openpty')),
        'v199_system_settings_api': '/api/system/settings' in source and '/api/system/settings/open' in source,
        'v199_locale_allowlist': all(x in source for x in ('SUPPORTED_LOCALES', 'ar')),
        'v199_system_settings_ui': 'id=\"systemsettings\"' in ui and 'function loadSystemSettings()' in ui,
        'v199_modern_design_system': 'cf-v199-design' in ui,
        'v199_default_english': '\"locale\": \"en\"' in source and 'APP_VERSION = \"1.9.9.1\"' in source,
        'v199_backup_results_mirrored': "function systemBackupResultTargets(){return ['systemBackupResult','systemSettingsBackupResult']" in ui and 'writeSystemBackupResult' in ui,
        'v199_locale_selector_sync': "if($('prefLocale'))$('prefLocale').value=selected;if($('sysAppLocale'))$('sysAppLocale').value=selected" in ui,
        'v199_manifest_validation_complete': manifest.get('validation',{}).get('status')=='passed' and manifest.get('validation',{}).get('tests_passed')==661 and manifest.get('validation',{}).get('test_modules')==36,
        'v199_twelve_locale_files': len([x for x in ('en','vi','es','fr','de','pt','ja','ko','zh','ru','ar','hi') if (ROOT/'locales'/f'{x}.json').is_file()])==12,
        'v198_xterm_vendor_tool': (ROOT/'tools'/'vendor_xterm.py').is_file(),
        'v198_windows_pty_requirement': (ROOT/'requirements-windows-pty.txt').is_file(),
        'v198_terminal_resize_api': '/api/dev/terminal/resize' in source and 'DEV_TERMINAL_MANAGER.resize' in source,
        'v1991_localized_error_runtime': all(x in ui for x in ('function cfErrorCode(', 'function cfErrorText(', 'function cfMakeError(', 'cfPermissionPrompt')),
        'v1991_stale_locale_fallback_reset': 'const target=typeof translated===\'string\'?translated:original;' in ui and 'const result=typeof translated===\'string\'?translated:sourceValue;' in ui,
        'v1991_mutation_observer_batching': 'function cfQueueTranslate(node)' in ui and 'queueMicrotask(' in ui,
        'v1991_locale_loader_error_catalog': 'errors = raw.get(\"errors\", {})' in source and 'error catalog is malformed' in source,
        'v1991_release_docs': (ROOT/'RELEASE_NOTES_1.9.9.1.md').is_file() and (ROOT/'TEST_RESULTS_1.9.9.1.md').is_file(),
        'v1991_i18n_check_tool': (ROOT/'tools'/'i18n_check.py').is_file(),
        'v1991_i18n_tests': (ROOT/'tests'/'test_v19991_i18n_fixes.py').is_file(),
        'test_suite_exists': (ROOT/'tests').is_dir(),
    }
    for name,ok in checks.items():
        print(('PASS' if ok else 'FAIL')+' '+name)
        if not ok: failures.append(name)
    parser=IDs(); parser.feed(ui); duplicates=sorted({x for x in parser.values if parser.values.count(x)>1})
    print(('PASS' if not duplicates else 'FAIL')+f' html_unique_ids ({len(set(parser.values))} unique)')
    if duplicates: failures.append('html_unique_ids: '+', '.join(duplicates[:20]))
    for name in ('en','vi','es','fr','de','pt','ja','ko','zh','ru','ar','hi'):
        try: json.loads((ROOT/f'locales/{name}.json').read_text())
        except Exception as exc: failures.append(f'locale_{name}: {type(exc).__name__}')
    print('PASS locales_json' if not any(x.startswith('locale_') for x in failures) else 'FAIL locales_json')
    py_files=list(ROOT.glob('*.py'))+list((ROOT/'tests').glob('*.py'))+list((ROOT/'tools').glob('*.py'))+list((ROOT/'sandbox'/'netlab').glob('*.py'))
    for path in py_files:
        try: compile(path.read_text(encoding='utf-8'),str(path),'exec')
        except Exception as exc: failures.append(f'python_syntax:{path.relative_to(ROOT)}:{type(exc).__name__}')
    print(('PASS' if not any(x.startswith('python_syntax:') for x in failures) else 'FAIL')+f' python_syntax ({len(py_files)} files)')
    node=shutil.which('node')
    if node:
        with tempfile.TemporaryDirectory(prefix='cf-release-js-') as temp:
            js=Path(temp)/'inline.js'; js.write_text('\n;\n'.join(parser.scripts),encoding='utf-8')
            result=subprocess.run([node,'--check',str(js)],capture_output=True,text=True,timeout=15,check=False)
            if result.returncode: failures.append('javascript_syntax: '+result.stderr[:500])
        print(('PASS' if result.returncode==0 else 'FAIL')+' javascript_syntax')
    else:
        warnings.append('Node.js unavailable; inline JavaScript syntax check skipped.')
        print('SKIP javascript_syntax (Node.js not installed)')
    print(f'RELEASE_PREFLIGHT version={version} failures={len(failures)} warnings={len(warnings)}')
    for item in failures: print('ERROR '+item)
    for item in warnings: print('WARNING '+item)
    return 1 if failures else 0
if __name__=='__main__': raise SystemExit(main())
