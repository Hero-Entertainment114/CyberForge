-- v2.0.3 Security Operations normalized telemetry and incident schema.
CREATE TABLE IF NOT EXISTS security_incidents(
  incident_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  event_count BIGINT NOT NULL DEFAULT 0,
  assigned_to TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  closed_at TEXT
);
CREATE TABLE IF NOT EXISTS security_events(
  event_id TEXT PRIMARY KEY,
  incident_id TEXT,
  source TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  host TEXT,
  node_id TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  process_name TEXT,
  rule_id TEXT,
  details_json TEXT NOT NULL,
  UNIQUE(source, source_event_id)
);
CREATE INDEX IF NOT EXISTS idx_security_events_incident_time ON security_events(incident_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_security_events_source_time ON security_events(source, observed_at);
CREATE INDEX IF NOT EXISTS idx_security_incidents_status_severity ON security_incidents(status, severity, updated_at);
CREATE TABLE IF NOT EXISTS security_playbook_runs(
  run_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  playbook_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_by_id TEXT NOT NULL,
  approved_by TEXT,
  approved_by_id TEXT,
  created_at TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  approved_at TEXT,
  executed_at TEXT,
  result_json TEXT,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS idx_security_playbook_incident ON security_playbook_runs(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_security_playbook_status ON security_playbook_runs(status, expires_at);
