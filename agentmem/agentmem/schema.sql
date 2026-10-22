-- agentmem SQLite schema (spec §5). WAL mode set by the store at open time.
-- Long-term tiers are tables; the working set is cached in RAM and mirrored to
-- working_set so it survives restarts. Ground truth (observations, payloads,
-- confirmed findings) is append-only; reflection writes new derived rows.

CREATE TABLE IF NOT EXISTS kv_meta (key TEXT PRIMARY KEY, value TEXT);

-- nodes: semantic + procedural + hypotheses + chains share this table
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  canonical_key TEXT,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  importance INTEGER DEFAULT 5,
  confidence REAL DEFAULT 0.5,
  trust TEXT DEFAULT 'agent_asserted',
  status TEXT DEFAULT 'suspected',          -- suspected | confirmed | invalidated
  pinned INTEGER DEFAULT 0,
  strength REAL DEFAULT 20.0,               -- Ebbinghaus S
  created_step INTEGER,
  created_ts REAL,
  last_access_step INTEGER,
  embedding BLOB,
  UNIQUE(type, canonical_key)
);
CREATE INDEX IF NOT EXISTS ix_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS ix_nodes_key  ON nodes(canonical_key);
CREATE INDEX IF NOT EXISTS ix_nodes_pin  ON nodes(pinned);

CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY,
  src_id INTEGER NOT NULL,
  dst_id INTEGER NOT NULL,
  rel_type TEXT NOT NULL,
  attrs_json TEXT DEFAULT '{}',
  weight REAL DEFAULT 1.0,
  confidence REAL DEFAULT 0.5,
  trust TEXT DEFAULT 'agent_asserted',
  created_step INTEGER,
  valid_from INTEGER,
  valid_to INTEGER,                         -- NULL => currently holds (bi-temporal)
  provenance TEXT DEFAULT '[]',
  FOREIGN KEY(src_id) REFERENCES nodes(id),
  FOREIGN KEY(dst_id) REFERENCES nodes(id)
);
CREATE INDEX IF NOT EXISTS ix_edges_src ON edges(src_id, rel_type);
CREATE INDEX IF NOT EXISTS ix_edges_dst ON edges(dst_id, rel_type);

-- capability tables = the chain-matcher join target
CREATE TABLE IF NOT EXISTS provides (
  node_id INTEGER NOT NULL, token TEXT NOT NULL, attrs_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(node_id, token, attrs_json)
);
CREATE TABLE IF NOT EXISTS requires (
  node_id INTEGER NOT NULL, token TEXT NOT NULL, attrs_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(node_id, token, attrs_json)
);
CREATE INDEX IF NOT EXISTS ix_provides_tok ON provides(token);
CREATE INDEX IF NOT EXISTS ix_requires_tok ON requires(token);

-- episodic: lossless, append-only, never deleted
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY, step INTEGER, ts REAL,
  request TEXT, response_meta TEXT, blob_ref TEXT,
  trust TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS payloads (
  id INTEGER PRIMARY KEY, node_id INTEGER, endpoint_id INTEGER, param_id INTEGER,
  template TEXT, value TEXT, outcome TEXT, success INTEGER, obs_id INTEGER, step INTEGER
);
CREATE INDEX IF NOT EXISTS ix_payloads_target ON payloads(endpoint_id, param_id);

-- reflection layer (derived; separate from ground truth)
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY, node_id INTEGER, kind TEXT, text TEXT, step INTEGER
);
CREATE TABLE IF NOT EXISTS summaries (
  scope_type TEXT, scope_key TEXT, level INTEGER, text TEXT, step INTEGER,
  PRIMARY KEY(scope_type, scope_key, level)
);

-- chains materialized for fast reload + audit
CREATE TABLE IF NOT EXISTS chains (
  id INTEGER PRIMARY KEY, goal TEXT, score REAL, severity INTEGER,
  status TEXT, narrative TEXT, step INTEGER, dedup_key TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS chain_steps (
  chain_id INTEGER, ord INTEGER, node_id INTEGER, edge_id INTEGER,
  PRIMARY KEY(chain_id, ord)
);

-- secrets vault (private memory space, §6) — referenced by handle only
CREATE TABLE IF NOT EXISTS secrets (
  handle TEXT PRIMARY KEY, kind TEXT, value_enc BLOB, subject TEXT,
  acquired_obs INTEGER, valid INTEGER DEFAULT 1
);

-- persisted working set (MemGPT working-context block) for restart
CREATE TABLE IF NOT EXISTS working_set (
  key TEXT PRIMARY KEY, value_json TEXT, updated_step INTEGER
);
