-- CyberForge Server Edition v2.0.5 Threat Intelligence
CREATE TABLE IF NOT EXISTS threat_feeds(
 feed_id TEXT PRIMARY KEY, name TEXT NOT NULL, feed_type TEXT NOT NULL, url TEXT NOT NULL,
 config_json TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 0, last_sync_at TEXT,
 last_status TEXT NOT NULL DEFAULT 'never', last_error TEXT NOT NULL DEFAULT '', etag TEXT, last_modified TEXT,
 object_count BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threat_iocs(
 ioc_id TEXT PRIMARY KEY, ioc_type TEXT NOT NULL, value_norm TEXT NOT NULL, source_feed TEXT NOT NULL,
 source_object_id TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL DEFAULT 50, severity TEXT NOT NULL DEFAULT 'medium',
 description TEXT NOT NULL DEFAULT '', tags_json TEXT NOT NULL DEFAULT '[]', metadata_json TEXT NOT NULL DEFAULT '{}',
 valid_from TEXT, valid_until TEXT, revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 UNIQUE(ioc_type,value_norm,source_feed)
);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_lookup ON threat_iocs(ioc_type,value_norm,revoked,valid_until);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_source ON threat_iocs(source_feed,updated_at);
CREATE TABLE IF NOT EXISTS threat_objects(
 object_id TEXT NOT NULL, source_feed TEXT NOT NULL, object_type TEXT NOT NULL, modified_at TEXT NOT NULL DEFAULT '',
 summary_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(object_id,source_feed)
);
CREATE TABLE IF NOT EXISTS threat_relationships(
 source_object TEXT NOT NULL, target_object TEXT NOT NULL, relationship_type TEXT NOT NULL, source_feed TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(source_object,target_object,relationship_type,source_feed)
);
CREATE TABLE IF NOT EXISTS threat_intel_cache(
 cache_key TEXT PRIMARY KEY, result_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_cache_expiry ON threat_intel_cache(expires_at);
