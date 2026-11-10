-- CyberForge Server Edition v2.1.0 Official Stable: Detection Engineering.
-- Portable PostgreSQL migration; runtime initialization is idempotent as well.
CREATE TABLE IF NOT EXISTS detection_rules(
  rule_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  state TEXT NOT NULL,
  current_version BIGINT NOT NULL,
  active_version BIGINT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detection_rule_versions(
  rule_id TEXT NOT NULL,
  version BIGINT NOT NULL,
  definition_json TEXT NOT NULL,
  validation_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  published_by TEXT,
  published_at TEXT,
  PRIMARY KEY(rule_id, version)
);
CREATE INDEX IF NOT EXISTS idx_detection_rule_state ON detection_rules(state, updated_at);
CREATE INDEX IF NOT EXISTS idx_detection_rule_version_state ON detection_rule_versions(rule_id, state, version);
CREATE TABLE IF NOT EXISTS detection_matches(
  match_id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  rule_version BIGINT NOT NULL,
  event_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(rule_id, rule_version, event_id)
);
CREATE INDEX IF NOT EXISTS idx_detection_matches_event ON detection_matches(event_id, created_at);
CREATE INDEX IF NOT EXISTS idx_detection_matches_rule ON detection_matches(rule_id, created_at);
