-- CyberForge Server Edition v2.0.4: cross-incident correlation relationships.
CREATE TABLE IF NOT EXISTS security_incident_links(
  incident_a TEXT NOT NULL,
  incident_b TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  relation TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(incident_a, incident_b),
  CHECK(incident_a < incident_b)
);
CREATE INDEX IF NOT EXISTS idx_security_incident_links_b ON security_incident_links(incident_b, confidence);
