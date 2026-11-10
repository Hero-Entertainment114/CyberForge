-- v2.0.2 distributed AI queue additions. Runtime also applies these idempotently.
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS payload_ciphertext BYTEA;
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS result_ciphertext BYTEA;
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS lease_until BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ai_jobs ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS ai_model_slots (
  deployment_id TEXT NOT NULL,
  slot_no INTEGER NOT NULL,
  lease_owner TEXT,
  lease_until BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (deployment_id, slot_no)
);
CREATE INDEX IF NOT EXISTS idx_ai_jobs_lease ON ai_jobs(status, lease_until, priority, created_at);

-- Distributed, reclaimable workflow execution lease.
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS execution_owner TEXT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS execution_lease_until BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_workflows_execution_lease ON workflows(status, execution_lease_until);
