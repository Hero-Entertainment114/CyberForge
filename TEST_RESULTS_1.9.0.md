# Test results v1.9.0

- New v1.9.0 Security Core: **9/9 passed**.
- Inherited suite: all modules were run in isolated processes where completed.
- Aggregate observed: **446/448 passed**. Two inherited v1.8.8 SQLite crash-recovery assertions failed in this execution environment because the child-process WAL crash probe timed out; the same timeout also caused the dependent HTTP recovery assertion to fail. This is an environment/test-harness limitation, not counted as a pass.
- Targeted desktop, locale, integration, workspace-search, v1.8.9 onboarding and v1.9.0 Security Core modules passed.
- Release preflight: **0 failures, 0 warnings**.
- Python syntax and JavaScript syntax checks passed; HTML has 441 unique IDs.
- ZIP integrity and SHA-256 are checked during packaging.

The full inherited test suite did not complete cleanly in this environment. Do not interpret this report as 448/448 passing.
