"""CyberForge isolated plugin example. Input is JSON on stdin; output must be JSON."""
import json
import sys

context = json.load(sys.stdin)
case = context.get("case") or {}
knowledge = context.get("knowledge") or []
iocs = context.get("threat_intel") or []

result = {
    "plugin": context.get("plugin_id"),
    "case_id": (case.get("case") or {}).get("id"),
    "knowledge_hits": len(knowledge),
    "local_ioc_hits": len(iocs),
    "proposals": [
        "Review each matched IOC against source, first-seen and confidence before creating a finding."
    ] if iocs else [],
    "notice": "Example output only. No findings were written and no network request was made."
}
json.dump(result, sys.stdout, ensure_ascii=False)
