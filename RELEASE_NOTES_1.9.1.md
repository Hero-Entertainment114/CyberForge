# CyberForge AIO v1.9.1

## Defensive Engineering & Security Advisor 2.0

### Offline security advisor
- Multi-language static review for Python, JavaScript, TypeScript, shell and generic configuration.
- Reports line numbers, severity, confidence, CWE category, bounded evidence and remediation guidance.
- Detects common dynamic evaluation, shell execution, unsafe deserialization, disabled TLS verification, unsafe DOM sinks, weak hash, wildcard CORS, debug flags, possible hard-coded secrets and SQL concatenation.
- Secret-like evidence is redacted before it is returned. This remains heuristic static analysis, not an LLM or complete SAST/DAST.

### Web posture review
- Reviews user-supplied headers and Set-Cookie values for HSTS, CSP, CORS, framing, content-type, referrer, permissions, cross-origin policies, server banners and cookie flags.
- Cookie values are redacted from findings.
- No web request is sent. Missing headers do not prove an exploitable vulnerability.

### Defensive traffic lab
- Replaced the coarse one-line capacity estimate with a bounded discrete-time queue model.
- Models legitimate demand, virtual bot-like event sources, per-source rate limiting, challenge filtering, cache hit ratio, bounded queues and service capacity.
- Reports legitimate availability, filtered synthetic events, queue backlog and dropped events.
- Hard caps: 200 virtual agents, 1,000 synthetic events per agent per second, 120 seconds, 50,000 queue entries and 24 million total synthetic events.
- **No real traffic, packets, sockets, botnet, exploit or external target is used.**

### Privacy posture
- Extends exposure review to optional browser hints supplied by the user.
- Does not inspect hardware/device state automatically, alter operating-system network settings or claim complete anonymity.

### Static sample triage
- Combines code-level findings with contextual indicators for persistence, credential-store references, defense-evasion strings and network/download references.
- Samples are not executed, imported, unpacked or connected to a network. This is not a malware detonation sandbox.

### Compatibility
- v1.9.0 APIs and workspace remain available; v1.9.1 uses a new `/api/v191/` namespace.
- New analysis endpoints use the existing `static_analysis` permission policy.
- No new third-party runtime dependency is required.
