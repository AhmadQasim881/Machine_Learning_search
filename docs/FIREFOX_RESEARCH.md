# agentmem for Firefox source-code security research

`agentmem.ResearchMemory` is the persistent **research memory and evidence system**
for authorized Firefox source-code security research. It is the memory layer of the
platform described in `Firefox_RCE_Roadmap.md` — it stores and connects evidence
produced by external analyzers (Searchfox-derived adapters, Clang/LibTooling
indexes, CodeQL, compiler tooling, test harnesses, human review). **It does not
implement those analyzers, run builds, or validate exploits**, and it never infers a
data-flow relationship from two values sharing a variable name.

See also: **[RESEARCH_SCHEMA.md](RESEARCH_SCHEMA.md)** (entities, states, migration,
backup). What "memory vs. static analysis vs. validation vs. demonstrated impact"
means is in the project README.

## Record model

Everything is scoped to a **snapshot** (a repository revision). Code facts:

- **value identities** — a scoped value `(snapshot, case-sensitive path, qualified
  symbol, source range, value name, role)`. Roles: `source`, `sink` (+`sink_type`),
  `transform`, `param`, `return`, `field`, `value`.
- **flow edges** — explicit, provenance-bearing transitions between value
  identities, interprocedural edges carrying callsite, caller/callee, arg→param and
  return→receiver mappings, and field identity.
- **guards** — sanitizers/validators attached to a specific flow edge.
- **code_symbols** — C++/Rust/JS/WebIDL/IPDL symbols with language, kind,
  case-sensitive path+range, and trust domain.
- **symbol_relations** — `calls` (with `dispatch`: direct/virtual/function_pointer/
  unresolved), `inherits`, `implements`, `binds`, `crosses_boundary`.
- **boundaries** — process / sandbox / privilege / origin / principal / ipc.
- **evidence / hypotheses / validation_runs / findings** — the investigation
  lifecycle, each with its own state field (see RESEARCH_SCHEMA.md).

Raw analyzer output, SARIF, build/sanitizer logs, crash dumps, and testcases are
preserved **verbatim** as immutable content-addressed artifacts; a bounded,
sanitized, secret-redacted projection is what goes into prompts and search.

## Python example (one investigation)

```python
from agentmem import ResearchMemory

m = ResearchMemory("firefox.db", actor="researcher:alice")
snap = m.register_snapshot("firefox", "<full 40-char commit sha>", scope="dom/media")

# 1. symbols + a trust boundary (from an index adapter)
p = m.add_provenance(snap, tool="searchfox-adapter", actor="searchfox", actor_kind="tool",
                     trust="tool_verified")
m.register_symbol(snap, "cpp:mozilla::MediaParse", qualified_name="mozilla::MediaParse",
                  language="cpp", kind="function", path="dom/media/Parse.cpp", start_line=120,
                  trust_domain="content-process", provenance_id=p)
b = m.add_boundary(snap, "content->parent", kind="process")

# 2. scoped value identities + an EXPLICIT flow edge (from a CodeQL path), with evidence
ev = m.record_analysis_result(snap, tool="codeql", query_id="cpp/tainted-alloc-size",
                              raw=open_sarif_text, status="supported", trust="tool_verified")
src  = m.add_value_identity(snap, "dom/media/Parse.cpp", "size", role="source",
                            symbol_id="mozilla::MediaParse", start_line=124)
sink = m.add_value_identity(snap, "dom/media/Buf.cpp", "n", role="sink",
                            symbol_id="mozilla::Buf::Alloc", start_line=40, sink_type="buffer")
edge = m.add_flow_edge(snap, src, sink, kind="interprocedural", status="supported",
                       trust="tool_verified", caller_symbol="mozilla::MediaParse",
                       callee_symbol="mozilla::Buf::Alloc", arg_index=0, param_name="n",
                       evidence_id=ev["evidence_id"])

# 3. a guard found on that path (prevents an "unguarded confirmed chain")
m.add_guard(snap, flow_edge_id=edge, guard_symbol="CheckedInt", kind="validator",
            condition="CheckedInt<size_t> bound check", status="active")

# 4. hypothesis + counter-evidence, then review the chain's gaps
h = m.add_hypothesis(snap, "unchecked size reaches Buf::Alloc", invariant="allocation size bounded")
m.link_evidence(h, "supports", flow_edge_id=edge)
for c in m.chains(snap):
    print(c["status"], c["goal"], c["narrative"])   # 'blocked' while the guard holds
```

## Importing analyzer output (CodeQL / SARIF)

Instead of hand-entering taint facts, import a CodeQL run directly — its
`codeFlows` become scoped value identities + explicit flow edges + evidence, with
the raw SARIF preserved verbatim as an immutable artifact:

```python
from agentmem.importers import import_sarif
summary = import_sarif(m, snap, open("results.sarif").read())
# {'results': N, 'flows': N, 'value_identities': N, 'flow_edges': N, 'evidence': N, ...}
```

Identities come from exact SARIF locations (uri + region + logical symbol) and
edges from CodeQL's own threadFlow ordering — nothing is inferred from a shared
name. A CodeQL path is tool **evidence**, so edges import as `supported` /
`tool_verified` (never `demonstrated`; that needs dynamic validation). `ruleId` is
mapped to a sink type (e.g. `cpp/sql-injection` → `sql`, `cpp/command-line-injection`
→ `command`). This is the adapter that turns the memory from a manual ledger into a
pipeline; a Searchfox/compile-commands symbol importer and an ASan-log parser are
the natural next adapters under the same contract.

## MCP for Claude Desktop / Claude Code

Run the research MCP server (stdio):

```bash
cd agentmem && pip install -e ".[mcp]"
AGENTMEM_DB=/abs/firefox.db AGENTMEM_ACTOR="researcher:alice" python -m agentmem.research_mcp
```

Claude Code registration (one DB per research scope):

```bash
claude mcp add --env AGENTMEM_DB=/abs/firefox.db --env AGENTMEM_ACTOR=alice \
  --transport stdio agentmem-firefox -- /abs/agentmem/.venv/bin/python -m agentmem.research_mcp
```

Claude Desktop (`claude_desktop_config.json`): a `mcpServers` entry with
`"command": "/abs/.venv/bin/python"`, `"args": ["-m","agentmem.research_mcp"]`, and
`env` carrying `AGENTMEM_DB`/`AGENTMEM_ACTOR` (see CODE_REVIEW_INTEGRATION.md for the
exact config shape and gotchas).

### Tools

| Tool | Responsibility |
|---|---|
| `register_repository_snapshot` | register/return a revision scope |
| `record_source_reference` | an exact revision-scoped source location |
| `record_value_identity` | a scoped flow-graph node |
| `record_analysis_evidence` | analysis output as artifact + bounded evidence |
| `link_flow_transition` | an explicit flow edge between identities |
| `record_hypothesis` / `record_counter_evidence` | hypotheses + contradicting evidence |
| `record_validation_run` | a build/test/repro outcome |
| `query_history` | revision-aware recall (exact first; historical labelled stale) |
| `review_chain` | which transitions are demonstrated and which are missing |
| `reclassify_sink` | append-only reclassification (stales the old chain) |
| `invalidate_changed_paths` | active staleness: mark records on changed paths stale, retract their chains |
| `export_evidence_bundle` | structured bundle for human review |

### Response contract

Every tool returns `{"ok": true, "data": ...}` or
`{"ok": false, "error": {"code": "<CODE>", "message": ...}}` with a stable code:
`INVALID_ARGUMENT`, `NOT_FOUND`, `REVISION_MISMATCH`, `STALE_EVIDENCE`, `CONFLICT`,
`BACKEND_UNAVAILABLE`, `RESOURCE_LIMIT`. Mutations accept an `idempotency_key`; a
repeated call replays the original id instead of creating a duplicate (a key reused
for a different op is a `CONFLICT`). Transport (`research_mcp.py`) is kept separate
from the contract (`research_tools.py`) and from storage (`research.py`).

## Review workflow (maps to the roadmap's stages)

1. **Surface mapping** — register the snapshot; record entry-point symbols,
   bindings/IPDL, and trust boundaries.
2. **Candidate discovery** — record analysis evidence and scoped value identities;
   open hypotheses with their supporting/counter evidence.
3. **Root-cause** — link explicit flow edges; attach the guards you find; use
   `review_chain` to see the exact missing transitions.
4. **Impact** — a chain is `demonstrated` only when every transition is; keep
   `impact_state` separate — a sandboxed-process defect does not by itself cross a
   boundary.
5. **Validation** — record build/test/repro runs; preserve crash/sanitizer logs as
   artifacts; a reproduced crash is not automatically exploitable impact.

## Retrieval benchmark (measured)

`benchmarks/bench_retrieval.py` compares the naive N+1 scan against the SQL-side
`search_evidence` at several store sizes. Numbers below were measured in this
environment (Python 3.13.16, Linux, SQLite with FTS5):

```
$ python benchmarks/bench_retrieval.py
       N | baseline stmts  baseline ms | sql_side stmts  sql_side ms | backend
    1000 |           1001        20.46 |              5         0.30 | fts5
   10000 |          10001       349.18 |              5         0.35 | fts5
   50000 |          50001      2716.15 |              5         0.53 | fts5
```

The SQL-side bounded query issues a **constant** number of statements (~5) and stays
sub-millisecond as the store grows 50×, while the N+1 baseline issues ~N statements
and grows linearly. Re-run on your machine for local numbers (nothing is
hard-coded). Text search uses FTS5 when the SQLite build has it, otherwise a
documented `LIKE` fallback (`ResearchMemory.text_search_backend()` reports which).

## Limitations (honest scope)

- agentmem is memory/evidence only. Indexers, CodeQL, builds, sanitizers, and
  fuzzing are **out of scope here** — their results are recorded, not produced.
- A chain's correctness is only as good as the flow edges and guards an analyzer or
  reviewer recorded; agentmem guarantees it will not *invent* edges, not that the
  recorded ones are complete.
- The secrets-vault cipher is stdlib obfuscation-at-rest (set `AGENTMEM_VAULT_KEY`
  or back it with a KMS for production).
- For authorized security research only.
