# Secure Code Review Playbook

- Treat user-controlled input as untrusted and validate it at trust boundaries.
- Prefer parameterized SQL queries; never concatenate untrusted values into SQL.
- Avoid unsafe deserialization. Use safe loaders and validate expected schemas.
- Verify TLS certificates. Do not disable certificate validation in production.
- Store credentials in a secrets manager or environment configuration, never in source control.
- Apply least privilege to files, processes, tokens, service accounts and cloud roles.
- Pin and review dependencies; maintain an SBOM and monitor advisories.
- Treat SAST findings as leads. Confirm data flow, reachability, impact and compensating controls.
- For fixes, make the smallest behavior-preserving change and add a regression test.
