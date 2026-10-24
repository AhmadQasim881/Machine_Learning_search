-- agentmem research-evidence schema (schema_version 2).
-- Applied by agentmem.migrations as the v1 -> v2 forward migration. Purely
-- additive: it creates new tables only and never alters or drops the v1 web/
-- code-review tables, so an existing database migrates without data loss.
--
-- Design rule (see README "Memory vs. analysis"): these tables record EVIDENCE
-- produced by analysis tools, exact source review, or explicit hypotheses. A
-- code-flow relationship is an explicit `flow_edges` row with provenance — it is
-- NEVER inferred from two values sharing a variable name. Scoped `value_identities`
-- make a `data` in one function a different identity from a `data` in another.

-- ---------------------------------------------------------------------------
-- Revision scope: every code-related fact references a snapshot.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS snapshots (
  id            INTEGER PRIMARY KEY,
  snapshot_uid  TEXT UNIQUE NOT NULL,       -- content id: repo|commit|dirty|patch|scope
  repo_id       TEXT NOT NULL,
  commit_id     TEXT NOT NULL,              -- full commit/changeset identifier
  dirty         INTEGER NOT NULL DEFAULT 0,
  patch_digest  TEXT,                        -- sha256 of the working-tree patch when dirty
  scope         TEXT,                        -- component / analysis scope
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_snapshots_repo ON snapshots(repo_id, commit_id);

-- ---------------------------------------------------------------------------
-- Immutable, content-addressed artifacts (raw evidence is never truncated).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS artifacts (
  id            INTEGER PRIMARY KEY,
  sha256        TEXT UNIQUE NOT NULL,
  media_type    TEXT,
  size          INTEGER NOT NULL,
  storage_path  TEXT NOT NULL,               -- path under the artifact store (by digest)
  producing_run TEXT,
  original_name TEXT,                         -- metadata only, never a storage path
  retention     TEXT NOT NULL DEFAULT 'keep', -- keep | expirable
  created_ts    REAL
);

-- Who/what produced a claim, and under what configuration.
CREATE TABLE IF NOT EXISTS provenance (
  id             INTEGER PRIMARY KEY,
  snapshot_id    INTEGER,
  tool           TEXT,
  tool_version   TEXT,
  query_id       TEXT,                        -- query/rule id
  actor          TEXT,                        -- researcher/agent/tool identifier
  actor_kind     TEXT,                        -- human | agent | tool | import
  trust          TEXT DEFAULT 'agent_asserted',
  config_digest  TEXT,
  raw_artifact_id INTEGER,
  ts             REAL,
  meta_json      TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)     REFERENCES snapshots(id),
  FOREIGN KEY(raw_artifact_id) REFERENCES artifacts(id)
);

-- ---------------------------------------------------------------------------
-- Source references: an exact, revision-scoped source location.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS source_refs (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER NOT NULL,
  path          TEXT NOT NULL,                -- repo-relative, CASE-SENSITIVE
  start_line    INTEGER, start_col INTEGER, end_line INTEGER, end_col INTEGER,
  symbol_id     TEXT,                          -- stable/qualified symbol
  language      TEXT,
  excerpt_artifact_id INTEGER,                 -- immutable excerpt bytes
  excerpt_digest TEXT,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)         REFERENCES snapshots(id),
  FOREIGN KEY(excerpt_artifact_id) REFERENCES artifacts(id)
);
CREATE INDEX IF NOT EXISTS ix_srcref_snap_path ON source_refs(snapshot_id, path);
CREATE INDEX IF NOT EXISTS ix_srcref_symbol    ON source_refs(symbol_id);

-- ---------------------------------------------------------------------------
-- Scoped value identities = the nodes of the explicit flow graph.
-- A value's identity is (snapshot, case-sensitive path, qualified symbol,
-- source range, value name, role). Two identically-named locals in different
-- functions have different vid_keys and therefore never connect.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS value_identities (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER NOT NULL,
  vid_key       TEXT NOT NULL,                -- canonical scoped identity
  path          TEXT NOT NULL,                -- CASE-SENSITIVE
  symbol_id     TEXT,                          -- enclosing qualified symbol / stable id
  value_name    TEXT,
  start_line    INTEGER, end_line INTEGER,
  role          TEXT,                          -- source|sink|transform|param|return|field|value
  sink_type     TEXT,                          -- when role=sink
  language      TEXT,
  tool          TEXT, run_id TEXT,             -- analysis provenance when tool-derived
  source_ref_id INTEGER,
  provenance_id INTEGER,
  status        TEXT NOT NULL DEFAULT 'observed',
  version       INTEGER NOT NULL DEFAULT 1,
  valid_from    REAL, valid_to REAL,           -- append-only versioning (valid_to NULL => current)
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(source_ref_id) REFERENCES source_refs(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id),
  UNIQUE(snapshot_id, vid_key, version)
);
CREATE INDEX IF NOT EXISTS ix_vid_snap_role ON value_identities(snapshot_id, role);
CREATE INDEX IF NOT EXISTS ix_vid_symbol    ON value_identities(symbol_id);
CREATE INDEX IF NOT EXISTS ix_vid_key       ON value_identities(snapshot_id, vid_key);

-- ---------------------------------------------------------------------------
-- Explicit flow edges (interprocedural transitions carry callsite/arg/return).
-- status is per-transition; a chain's status is the WEAKEST transition on it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS flow_edges (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER NOT NULL,
  src_vid       INTEGER NOT NULL,
  dst_vid       INTEGER NOT NULL,
  kind          TEXT NOT NULL,                -- intraprocedural|interprocedural|field|return|alias
  callsite_path TEXT, callsite_line INTEGER,
  caller_symbol TEXT, callee_symbol TEXT,
  arg_index     INTEGER, param_name TEXT,     -- argument-to-parameter mapping
  return_to     TEXT,                          -- return-to-receiver mapping
  field_id      TEXT,                          -- field/object identity
  status        TEXT NOT NULL DEFAULT 'hypothesis', -- hypothesis|supported|demonstrated|rejected|blocked
  confidence    REAL DEFAULT 0.5,
  trust         TEXT DEFAULT 'agent_asserted',
  provenance_id INTEGER,
  evidence_id   INTEGER,
  version       INTEGER NOT NULL DEFAULT 1,
  valid_from    REAL, valid_to REAL,           -- append-only (valid_to NULL => current)
  superseded_by INTEGER,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(src_vid)       REFERENCES value_identities(id),
  FOREIGN KEY(dst_vid)       REFERENCES value_identities(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id)
);
CREATE INDEX IF NOT EXISTS ix_flow_snap_src ON flow_edges(snapshot_id, src_vid, valid_to);
CREATE INDEX IF NOT EXISTS ix_flow_snap_dst ON flow_edges(snapshot_id, dst_vid, valid_to);

-- ---------------------------------------------------------------------------
-- Guards / sanitizers: evidence-backed transitions attached to a flow path.
-- Modeled explicitly (NOT as the absence of a propagator). An active guard on a
-- path blocks that path from presenting as an unguarded confirmed chain unless a
-- separate bypass/incomplete evidence record is attached.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guards (
  id             INTEGER PRIMARY KEY,
  snapshot_id    INTEGER NOT NULL,
  in_vid         INTEGER,                      -- input value identity
  out_vid        INTEGER,                      -- cleaned output (nullable)
  flow_edge_id   INTEGER,                       -- the exact transition/path it covers
  guard_symbol   TEXT,
  path           TEXT, start_line INTEGER, end_line INTEGER,
  condition      TEXT,                          -- branch/predicate condition
  transformation TEXT,                          -- e.g. escaping / bound-check
  kind           TEXT,                          -- sanitizer|validator|guard
  limits         TEXT,                          -- applicability limits
  status         TEXT NOT NULL DEFAULT 'active',-- active|bypassed|incomplete|rejected
  provenance_id  INTEGER,
  evidence_id    INTEGER,
  version        INTEGER NOT NULL DEFAULT 1,
  valid_from     REAL, valid_to REAL,
  created_ts     REAL,
  meta_json      TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)  REFERENCES snapshots(id),
  FOREIGN KEY(in_vid)       REFERENCES value_identities(id),
  FOREIGN KEY(out_vid)      REFERENCES value_identities(id),
  FOREIGN KEY(flow_edge_id) REFERENCES flow_edges(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id)
);
CREATE INDEX IF NOT EXISTS ix_guards_edge ON guards(flow_edge_id);
CREATE INDEX IF NOT EXISTS ix_guards_snap ON guards(snapshot_id);

-- ---------------------------------------------------------------------------
-- Evidence: a raw artifact plus a bounded, sanitized, secret-redacted text
-- projection for prompts/search. evidence.status is the EVIDENCE state only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
  id                INTEGER PRIMARY KEY,
  snapshot_id       INTEGER,
  kind              TEXT,                      -- source_excerpt|static_analysis|dataflow|crash|sanitizer|test|doc|note
  value_identity_id INTEGER,
  source_ref_id     INTEGER,
  flow_edge_id      INTEGER,
  artifact_id       INTEGER,                   -- raw immutable bytes
  projection        TEXT,                      -- bounded + sanitized + redacted
  projection_truncated INTEGER NOT NULL DEFAULT 0,
  status            TEXT NOT NULL DEFAULT 'observed', -- observed|supported|reproduced|rejected|stale
  trust             TEXT DEFAULT 'agent_asserted',
  provenance_id     INTEGER,
  obs_id            INTEGER,                   -- FK episodic observations
  stale_reason      TEXT,
  version           INTEGER NOT NULL DEFAULT 1,
  valid_from        REAL, valid_to REAL,
  created_ts        REAL,
  meta_json         TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)       REFERENCES snapshots(id),
  FOREIGN KEY(value_identity_id) REFERENCES value_identities(id),
  FOREIGN KEY(source_ref_id)     REFERENCES source_refs(id),
  FOREIGN KEY(flow_edge_id)      REFERENCES flow_edges(id),
  FOREIGN KEY(artifact_id)       REFERENCES artifacts(id),
  FOREIGN KEY(provenance_id)     REFERENCES provenance(id),
  FOREIGN KEY(obs_id)            REFERENCES observations(id)
);
CREATE INDEX IF NOT EXISTS ix_evidence_snap_status ON evidence(snapshot_id, status);
CREATE INDEX IF NOT EXISTS ix_evidence_vid        ON evidence(value_identity_id);
CREATE INDEX IF NOT EXISTS ix_evidence_kind       ON evidence(kind);

-- ---------------------------------------------------------------------------
-- Hypotheses, their evidence links, validation runs, findings.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hypotheses (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER,
  statement     TEXT NOT NULL,
  invariant     TEXT,
  scope         TEXT,
  status        TEXT NOT NULL DEFAULT 'open',  -- open|supported|rejected|superseded
  next_action   TEXT,
  trust         TEXT DEFAULT 'agent_asserted',
  provenance_id INTEGER,
  version       INTEGER NOT NULL DEFAULT 1,
  valid_from    REAL, valid_to REAL,
  superseded_by INTEGER,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id)
);
CREATE INDEX IF NOT EXISTS ix_hyp_snap_status ON hypotheses(snapshot_id, status);

CREATE TABLE IF NOT EXISTS hypothesis_evidence (
  id                INTEGER PRIMARY KEY,
  hypothesis_id     INTEGER NOT NULL,
  evidence_id       INTEGER,
  flow_edge_id      INTEGER,
  validation_run_id INTEGER,
  relation          TEXT NOT NULL,             -- supports|contradicts|tests|requires|crosses_boundary
  actor             TEXT, rationale TEXT, created_ts REAL,
  FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id),
  FOREIGN KEY(evidence_id)   REFERENCES evidence(id),
  FOREIGN KEY(flow_edge_id)  REFERENCES flow_edges(id)
);
CREATE INDEX IF NOT EXISTS ix_hypev_hyp ON hypothesis_evidence(hypothesis_id);

CREATE TABLE IF NOT EXISTS validation_runs (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER,
  hypothesis_id INTEGER,
  kind          TEXT,                          -- test|build|repro|fuzz
  status        TEXT NOT NULL DEFAULT 'not_run', -- not_run|passed|failed|inconclusive|intermittent
  build_manifest_digest TEXT,
  config_digest TEXT,
  artifact_id   INTEGER,                       -- logs bundle
  repeat_summary TEXT,                          -- observed_once|repeatable|intermittent|not_reproduced
  provenance_id INTEGER,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id),
  FOREIGN KEY(artifact_id)   REFERENCES artifacts(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id)
);
CREATE INDEX IF NOT EXISTS ix_valrun_snap ON validation_runs(snapshot_id, status);

CREATE TABLE IF NOT EXISTS findings (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER,
  fingerprint   TEXT UNIQUE,                   -- defect fingerprint (not report title)
  title         TEXT,
  root_cause    TEXT,
  status        TEXT NOT NULL DEFAULT 'draft', -- draft|in_review|accepted|duplicate|closed
  severity      TEXT,
  impact_state  TEXT NOT NULL DEFAULT 'unproven', -- unproven|suspected|demonstrated
  hypothesis_id INTEGER,
  provenance_id INTEGER,
  version       INTEGER NOT NULL DEFAULT 1,
  valid_from    REAL, valid_to REAL,
  superseded_by INTEGER,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
);
CREATE INDEX IF NOT EXISTS ix_findings_snap_status ON findings(snapshot_id, status);

-- Research chains composed from explicit flow edges (status = weakest transition).
CREATE TABLE IF NOT EXISTS research_chains (
  id           INTEGER PRIMARY KEY,
  snapshot_id  INTEGER,
  goal         TEXT,
  status       TEXT,                            -- hypothesis|supported|demonstrated|rejected|blocked
  severity     INTEGER,
  impact_state TEXT NOT NULL DEFAULT 'unproven',
  dedup_key    TEXT UNIQUE,
  narrative    TEXT,
  created_ts   REAL,
  meta_json    TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id) REFERENCES snapshots(id)
);
CREATE TABLE IF NOT EXISTS research_chain_steps (
  chain_id     INTEGER, ord INTEGER, flow_edge_id INTEGER,
  PRIMARY KEY(chain_id, ord),
  FOREIGN KEY(chain_id)     REFERENCES research_chains(id),
  FOREIGN KEY(flow_edge_id) REFERENCES flow_edges(id)
);

-- ---------------------------------------------------------------------------
-- Audit + idempotency.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
  id             INTEGER PRIMARY KEY,
  ts             REAL,
  actor          TEXT, session TEXT, correlation_id TEXT,
  op             TEXT, affected_table TEXT, affected_id INTEGER,
  old_state      TEXT, new_state TEXT, rationale TEXT,
  meta_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS ix_audit_affected ON audit_events(affected_table, affected_id);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  key         TEXT PRIMARY KEY,
  op          TEXT,
  result_kind TEXT,
  result_id   INTEGER,
  created_ts  REAL
);
