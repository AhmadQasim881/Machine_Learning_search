-- agentmem Firefox research records (schema_version 3). Applied by
-- agentmem.migrations as the additive v2 -> v3 forward migration.
--
-- These typed records hold repository intelligence produced by EXTERNAL analyzers
-- (Searchfox-derived adapters, Clang/LibTooling indexes, CodeQL, compiler tooling,
-- test harnesses, human review). agentmem stores this evidence and connects it; it
-- does NOT implement the analyzers. Every record is snapshot-scoped and carries
-- provenance, so a symbol or call edge is always tied to an exact revision.

-- C++/Rust/JS symbols, WebIDL declarations, IPDL protocols/messages.
CREATE TABLE IF NOT EXISTS code_symbols (
  id             INTEGER PRIMARY KEY,
  snapshot_id    INTEGER NOT NULL,
  symbol_id      TEXT NOT NULL,                -- stable/compiler symbol id or qualified name
  qualified_name TEXT,
  language       TEXT,                          -- cpp|rust|js|webidl|ipdl
  kind           TEXT,                          -- function|method|class|struct|webidl_interface|webidl_attribute|ipdl_protocol|ipdl_message|...
  path           TEXT, start_line INTEGER, end_line INTEGER,  -- CASE-SENSITIVE path
  trust_domain   TEXT,                          -- parent-process|content-process|gpu|rdd|socket|...
  provenance_id  INTEGER,
  created_ts     REAL,
  meta_json      TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id),
  UNIQUE(snapshot_id, symbol_id)
);
CREATE INDEX IF NOT EXISTS ix_codesym_name ON code_symbols(snapshot_id, qualified_name);
CREATE INDEX IF NOT EXISTS ix_codesym_sid  ON code_symbols(snapshot_id, symbol_id);
CREATE INDEX IF NOT EXISTS ix_codesym_domain ON code_symbols(snapshot_id, trust_domain);

-- Process / sandbox / privilege / origin / principal / IPC boundaries.
CREATE TABLE IF NOT EXISTS boundaries (
  id            INTEGER PRIMARY KEY,
  snapshot_id   INTEGER NOT NULL,
  name          TEXT NOT NULL,
  kind          TEXT,                           -- process|sandbox|privilege|origin|principal|ipc
  description   TEXT,
  created_ts    REAL,
  meta_json     TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id) REFERENCES snapshots(id),
  UNIQUE(snapshot_id, name)
);
CREATE INDEX IF NOT EXISTS ix_boundaries_snap ON boundaries(snapshot_id, kind);

-- Directed symbol relationships: calls, inheritance, interface impl, bindings,
-- and trust/process boundary crossings. A possible (virtual/pointer) call edge is
-- NOT an observed runtime execution — dispatch records the uncertainty.
CREATE TABLE IF NOT EXISTS symbol_relations (
  id             INTEGER PRIMARY KEY,
  snapshot_id    INTEGER NOT NULL,
  src_symbol     TEXT NOT NULL,
  dst_symbol     TEXT NOT NULL,
  relation       TEXT NOT NULL,                -- calls|inherits|implements|binds|crosses_boundary
  dispatch       TEXT,                          -- direct|virtual|function_pointer|unresolved
  callsite_path  TEXT, callsite_line INTEGER,
  boundary_id    INTEGER,
  confidence     REAL DEFAULT 0.5,
  provenance_id  INTEGER,
  created_ts     REAL,
  meta_json      TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY(snapshot_id)   REFERENCES snapshots(id),
  FOREIGN KEY(boundary_id)   REFERENCES boundaries(id),
  FOREIGN KEY(provenance_id) REFERENCES provenance(id)
);
CREATE INDEX IF NOT EXISTS ix_symrel_src ON symbol_relations(snapshot_id, src_symbol, relation);
CREATE INDEX IF NOT EXISTS ix_symrel_dst ON symbol_relations(snapshot_id, dst_symbol, relation);
