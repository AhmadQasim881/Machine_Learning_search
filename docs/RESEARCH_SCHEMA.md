# agentmem research schema & migration

The research-evidence layer adds, on top of the v1 web/code-review tables, a
revision-aware evidence model. This document is the schema + migration reference.

## Schema versions & migration path

`agentmem.migrations` records a `schema_version` in `kv_meta` and applies ordered,
**additive** forward steps on open. The base `schema.sql` (v1) is applied every
open with `CREATE ... IF NOT EXISTS`; migrations layer the rest.

| version | adds | file |
|---|---|---|
| 1 | web + first-gen code-review tables (nodes, edges, provides/requires, observations, chains, secrets, working_set) | `schema.sql` |
| 2 | snapshots, source_refs, value_identities, flow_edges, guards, evidence, hypotheses (+links), validation_runs, findings, research_chains, artifacts, provenance, audit_events, idempotency_keys; optional `evidence_fts` (FTS5) | `schema_research.sql` |
| 3 | code_symbols, symbol_relations, boundaries (Firefox record model) | `schema_firefox.sql` |

**Migration behavior**

- **Additive, lossless.** Every step only creates new tables/indexes; no v1 data is
  altered or dropped. An existing v1 or v2 database upgrades in place to v3 the
  first time it is opened, keeping all rows. (Regression-tested:
  `tests/test_research_foundation.py::test_existing_v1_db_migrates_without_data_loss`
  and `tests/test_firefox_and_backup.py::TestSchemaV3`.)
- **Refuses a newer database.** If a database's recorded version is greater than the
  library's `CURRENT_SCHEMA_VERSION`, `Store(...)` raises with a clear message to
  back up the file and upgrade agentmem — it never silently downgrades or risks
  data loss.
- **How to migrate:** just open the database (`Store(path)` /
  `ResearchMemory(path)` / `Memory(path)`); migration runs automatically. Back up
  first with `python -m agentmem.backup backup <db> <dir>` (see below).

## Entities (v2–v3)

- **snapshots** — a repository revision scope: `repo_id`, full `commit_id`, `dirty`,
  `patch_digest` (when dirty), `scope`. Identity (`snapshot_uid`) folds all of these
  in, so a patched run is a distinct snapshot from the clean commit. Every
  code-related fact references a snapshot.
- **artifacts** — immutable raw evidence by SHA-256 (`media_type`, `size`,
  `storage_path`, `original_name` as metadata only). Written atomically; verified on
  read.
- **provenance** — who/what produced a claim: `tool`+`tool_version`, `query_id`,
  `actor`+`actor_kind`, `trust`, `config_digest`, `raw_artifact_id`, timestamp.
- **source_refs** — exact, revision-scoped source location (case-sensitive `path`,
  range, `symbol_id`, language, optional excerpt artifact + digest).
- **value_identities** — scoped flow-graph nodes: `(snapshot, case-sensitive path,
  qualified symbol, source range, value name, role)`. `vid_key` is the canonical
  identity; two identically-named locals in different functions/files/case-distinct
  paths are different identities. Append-only versioned (`version`,
  `valid_from`/`valid_to`).
- **flow_edges** — EXPLICIT transitions between value identities: `kind`
  (intraprocedural/interprocedural/field/return/alias), `callsite_*`,
  `caller_symbol`/`callee_symbol`, `arg_index`/`param_name`, `return_to`,
  `field_id`, per-edge `status`, `confidence`, `trust`, `provenance_id`,
  `evidence_id`. Append-only versioned; `superseded_by` links a re-pointed edge.
- **guards** — evidence-backed sanitizers/validators attached to a specific flow
  edge: `in_vid`/`out_vid`, `guard_symbol`, location, `condition`,
  `transformation`, `kind`, `limits`, `status` (active/bypassed/incomplete/
  rejected).
- **evidence** — `kind`, links to a value identity/source ref/flow edge, a raw
  `artifact_id`, a bounded sanitized **projection** (+`projection_truncated`),
  `status`, `trust`, `provenance_id`, `obs_id`, `stale_reason`. Append-only
  versioned.
- **hypotheses** + **hypothesis_evidence** — a statement/invariant/scope with
  `status`; typed links (supports/contradicts/tests/requires/crosses_boundary) to
  evidence/flow edges/validation runs.
- **validation_runs** — `kind`, `status`, build/config digests, logs artifact,
  `repeat_summary`.
- **findings** — defect `fingerprint` (not the report title), `title`,
  `root_cause`, lifecycle `status`, `severity`, separate `impact_state`.
- **research_chains** / **research_chain_steps** — materialized composed chains
  (status = weakest transition).
- **code_symbols**, **symbol_relations**, **boundaries** (v3) — the Firefox record
  model (see docs/FIREFOX_RESEARCH.md).
- **audit_events** — append-only log of every state-changing op (actor, session,
  correlation id, old/new state, rationale).
- **idempotency_keys** — dedup key → (op, result) for MCP mutations.

## Separate state fields

A single `confirmed` flag is **not** used to mean several things. Each dimension
has its own field:

| field | values |
|---|---|
| evidence.status | `observed` · `supported` · `reproduced` · `rejected` · `stale` |
| hypotheses.status | `open` · `supported` · `rejected` · `superseded` |
| validation_runs.status | `not_run` · `passed` · `failed` · `inconclusive` · `intermittent` |
| flow_edges.status (chain transition) | `hypothesis` · `supported` · `demonstrated` · `rejected` · `blocked` |
| findings.status (lifecycle) | `draft` · `in_review` · `accepted` · `duplicate` · `closed` |
| findings.impact_state | `unproven` · `suspected` · `demonstrated` |

**Promotion rules.** Untrusted (`target_derived`), raw LLM output, and arbitrary
agent assertions can never independently reach `supported`/`reproduced`/
`demonstrated`. `reproduced` requires strong trust (`tool_verified`/
`human_verified`); consensus requires ≥2 real, independent-provenance,
acceptably-trusted evidence rows in a compatible snapshot and can establish at most
`supported`. A chain's status is the **weakest** transition on it, and an active
guard caps a step at `blocked`.

## Backup / restore

```bash
python -m agentmem.backup backup  <db_path> <dest_dir>   # metadata.db + artifacts/ + manifest.json
python -m agentmem.backup restore <dest_dir> <db_path>   # restores both, then verifies
python -m agentmem.backup verify  <db_path>              # every artifact row resolves by SHA-256
```

`restore` re-verifies that every `artifacts` row resolves to its bytes by digest,
so a restored database can be trusted before research resumes.

### Evidence bundles and artifact GC

- `ResearchMemory.export_bundle_to_dir(snapshot_id, dest_dir)` writes a
  self-contained, disclosure-grade bundle: `manifest.json` (snapshot identity,
  chains, findings, evidence metadata each with its artifact SHA-256) plus the
  referenced raw artifacts copied by digest into `artifacts/` (re-verified on
  copy), so another researcher can confirm the evidence resolves to its bytes.
- `Store.gc_artifacts(grace_seconds, only_expirable=True)` sweeps UNREFERENCED
  artifacts (not pointed at by any evidence / source ref / validation run /
  provenance). Only `retention='expirable'` artifacts older than the grace period
  are eligible; a `retention='keep'` artifact is never swept. Each sweep is
  audited.
