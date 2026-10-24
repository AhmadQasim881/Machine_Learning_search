# agentmem

Persistent, **chain-finding** memory for an autonomous web bug-bounty agent.
Synthesized from 28 agent-memory papers (MemGPT, Generative Agents, CoALA,
HippoRAG, AriGraph, Zep, A-Mem, Voyager, Reflexion, VulnBot, PentestAgent, …).

It gives an agent a durable memory that **never forgets** discovered endpoints,
params, tech, credentials, payloads tried + outcomes, and hypotheses — across a
long engagement **and across process restarts** — and, the headline, it **detects
multi-step exploit chains** (e.g. open-redirect → OAuth → token theft).

> **The core runs on the Python standard library + SQLite — no LLM, no
> embeddings, no installs.** Chain detection is deterministic graph search over
> typed capability tokens, not similarity. LLM/embedding enrichment is additive.

## Two layers

agentmem has two profiles over one SQLite engine:

1. **Web bug-bounty memory** (the original) — capability-unification chains over
   web findings (open-redirect → OAuth → token theft). This is what most of this
   README describes.
2. **Revision-aware research memory** (`agentmem.ResearchMemory`, schema v2–v3) —
   an evidence system for long-horizon **source-code security research** (e.g.
   authorized Firefox research). It does **not** infer data flow from matching
   variable names; a code chain exists only along **explicit, provenance-bearing,
   revision-scoped flow edges**. See **[docs/FIREFOX_RESEARCH.md](../docs/FIREFOX_RESEARCH.md)**
   and **[docs/RESEARCH_SCHEMA.md](../docs/RESEARCH_SCHEMA.md)**.

### Memory vs. static analysis vs. validation vs. demonstrated impact

agentmem is **research memory and an evidence system — not a static analyzer, a
build system, or a validator.** It records and connects what external tools and
human review establish; it never manufactures those facts. It keeps four things
deliberately separate, each with its own state field (never one `confirmed` flag):

| Layer | What it means here | Who establishes it |
|---|---|---|
| **Memory / evidence** | a recorded source ref, value identity, analysis result, note | an index, a tool, or exact human review — stored verbatim as an artifact |
| **Static analysis** | a candidate flow/transition between scoped identities | CodeQL/Clang/Searchfox-derived adapters (recorded as explicit flow edges) |
| **Validation** | a build/test/repro run and its outcome | an isolated build+test worker (recorded as a validation run) |
| **Demonstrated impact** | a chain whose every required transition is demonstrated | only when the evidence actually shows it — never because steps look plausible |

A recorded source, sink, or static-analysis result does **not** prove a
vulnerability; a reproduced crash does **not** prove exploitable impact; a chain is
**demonstrated** only when every transition on it is. agentmem enforces these as
distinct states and gates promotion on real, trusted, independent evidence.

---

## The key idea: chains as capability unification

An open-redirect and an OAuth endpoint look nothing alike to an embedding model,
so similarity-based memory never connects them. agentmem instead gives every
finding two structured sets:

- `provides[]` — capability tokens it yields (postconditions)
- `requires[]` — tokens it needs to be useful (preconditions)

A finding **`A ENABLES B`** iff some token in `A.provides` **unifies** with some
token in `B.requires` (name match + attribute constraints, e.g.
`controlled_redirect{host=app.target.com}` satisfies `requires
controlled_redirect{host ∈ *.target.com}`). A **chain** is a path whose
accumulated capabilities reach a high-value **goal** (`account_takeover`,
`token_theft`, `rce`, `privilege_escalation`, …). This connects *semantically
dissimilar* facts — which is exactly what finds chains.

---

## Quickstart (no dependencies)

```bash
cd agentmem
python -m unittest discover -s tests        # 110 tests, stdlib only
python examples/demo.py                      # web: 3 worked exploit-chain examples
python examples/codereview_demo.py           # code-review: taint-flow chains, SAME engine
```

```python
from agentmem import Memory

m = Memory("campaign.db")                     # persists to SQLite

# record confirmed findings as the agent proves them (oracle = how it was confirmed)
m.add_finding("open_redirect", host="app.target.com", path="/out", param="url",
              confirmed=True, oracle="302 reflects url", attrs={"host": "app.target.com"})
m.add_finding("oauth_redirect", host="app.target.com", path="/oauth/authorize",
              param="redirect_uri", confirmed=True, oracle="code delivered",
              attrs={"allow": "*.target.com"})

for ch in m.chains():                         # chains fall out of the graph
    print(ch["severity"], ch["narrative"])
    # 8  open_redirect @ app.target.com/out -> oauth_redirect @ ... ==> TOKEN_THEFT

print(m.next_probes())                         # backward chaining: what to try next
m.reflect(); m.close()                         # pin verified assets, persist
```

After a restart, `Memory("campaign.db").rehydrate()` reloads the working set
(targets, pinned findings/credentials, discovered chains, next-probe queue).

---

## Use it from Claude Desktop / Claude Code (MCP)

agentmem ships an **MCP server** so Claude can use it as persistent memory for
**long-horizon source-code security review** (and web triage). Claude records taint
facts as it reads code; the engine connects them into `source → … → sink` chains;
everything persists in one SQLite file, so the model's context stays small while
memory grows **across files and across sessions** — exactly what reviewing a repo
far larger than a context window (a messenger, a server) needs.

```bash
cd agentmem && pip install -e ".[mcp]"          # installs the MCP SDK (v2 or v1)

# register with Claude Code, one DB per repo, taint profile:
claude mcp add --env AGENTMEM_DB=/abs/path/telegram.db --env AGENTMEM_PROFILE=codereview \
  --transport stdio agentmem -- /abs/path/agentmem/.venv/bin/python -m agentmem.mcp_server
```

Tools Claude sees: `get_context` (reload what memory knows), `record_source/flow/
sink/sanitizer`, `get_chains` (the discovered data-flow chains = the finding list),
`next_probes` (the gap to trace next — a dangling sink/source), `recall`, `reflect`,
`invalidate`, `stats`. The **review method** is in
`skills/code-review/SKILL.md` (a Claude Code skill, or paste into Claude Desktop
project instructions). Full setup — Claude Desktop config, CLI commands, env vars,
gotchas, smoke test — in **`docs/CODE_REVIEW_INTEGRATION.md`**.

---

## Revision-aware research memory (Firefox / source-code review)

```python
from agentmem import ResearchMemory

m = ResearchMemory("firefox.db")                     # schema auto-migrates to v3
snap = m.register_snapshot("firefox", "<full commit sha>", scope="dom/media")

# scoped value identities (a `data` here is NOT the `data` in another function)
src  = m.add_value_identity(snap, "dom/Parser.cpp", "len", role="source", symbol_id="Parser::Parse", start_line=120)
sink = m.add_value_identity(snap, "ipc/Chan.cpp",  "n",  role="sink",  symbol_id="Chan::Write", start_line=40, sink_type="buffer")

# an EXPLICIT, provenance-bearing flow edge — never inferred from the name
m.add_flow_edge(snap, src, sink, kind="interprocedural", status="supported",
                trust="tool_verified", caller_symbol="Parser::Parse",
                callee_symbol="Chan::Write", arg_index=1, param_name="n")

for c in m.chains(snap):
    print(c["status"], c["goal"], c["narrative"])    # weakest-link status; 'demonstrated' only if every step is
```

Record analysis output / crashes as immutable evidence (`record_analysis_result`,
`record_crash_artifact`), model sanitizers as `add_guard` on the exact edge they
cover, and retrieve with `search_evidence` (free-text works without embeddings;
exact-revision first, other revisions labelled stale). Drive it from Claude via the
**Firefox research MCP** (`python -m agentmem.research_mcp`, tools with stable error
codes + idempotency). Back it up with `python -m agentmem.backup`. Full guide:
**[docs/FIREFOX_RESEARCH.md](../docs/FIREFOX_RESEARCH.md)**.

---

## Memory model (CoALA tiers)

| Tier | What it holds | Backed by |
|---|---|---|
| **Working** | current target, open hypotheses, auth/session, hot findings, recent-obs FIFO | `working_set` table (survives restart) |
| **Episodic** | every observation + every payload attempt **incl. failures** (negative memory) | `observations`, `payloads` (append-only, lossless) |
| **Semantic** | the **knowledge graph**: hosts, endpoints, params, tech, creds, findings, capabilities | `nodes`, `edges`, `provides`, `requires` |
| **Procedural** | reusable techniques/rules + chain templates | `technique` nodes |
| **Reflection** | failure lessons, per-target summaries, curated hypotheses | `lessons`, `summaries` |

Ground truth (observations, confirmed findings) is immutable; reflection writes
*new derived* records, never mutating or deleting it.

---

## What's implemented

- **Knowledge-graph store** (SQLite, WAL) — typed nodes + typed directed edges.
- **Capability engine + chain detector** — forward chaining (ENABLES edges +
  bounded best-first path search → goals) and backward chaining (`next_probes`).
- **Canonicalization/entity-resolution** — `/api/user/5` and `/api/user/9`
  collapse to one node (`{id}`); hosts normalized; distinct endpoints never
  auto-merged.
- **Hybrid retrieval** — exact SQL + graph BFS, composite rerank (relevance +
  importance + recency-in-**steps** + confidence), pinned nodes floored.
- **Forgetting with pinning** — Ebbinghaus decay as a *ranking signal only*;
  nothing is ever hard-deleted; verified assets pinned; stale facts
  soft-invalidated (bi-temporal, audit-preserving).
- **Security / anti-poisoning** — trust levels; `sanitize()` strips control chars
  + prompt-injection markers from target text; a **verification gate** (confirmed
  only via a concrete oracle); a **secrets vault** (values encrypted at rest,
  referenced by handle, redacted from any text).
- **Persistence/rehydrate** — everything reloads deterministically after a restart.

**Additive upgrades (interfaces present, not required):** embedding-based semantic
recall, and LLM enrichment (prose extraction, chain narration, summary/insight
curation). The whole chain engine works with neither.

## Module layout

```
agentmem/
  config.py         scoring weights, decay, trust ranks, CAPABILITY ONTOLOGY,
                    per-vuln-class provides/requires extractors, escalation rules
  schema.sql        SQLite DDL
  store.py          SQLiteStore: nodes/edges/capabilities/observations/chains/secrets, clock
  canonical.py      URL/host/path/param normalization + dedup keys + entity resolution
  capabilities.py   capability tokens + unification + escalation (the chain primitive)
  chains.py         forward + backward chaining, path search, chain materialization
  write.py          observe->extract->verify->attach-caps->link->trigger-chains pipeline
  retrieve.py       hybrid retrieval + composite rerank
  forget.py         Ebbinghaus decay (ranking only), pinning, soft-invalidate
  security.py       sanitize, trust policy, SecretsVault, redaction
  working.py        persisted working set + rehydrate()
  memory.py         Memory facade — the only API the agent uses
  profiles.py       DOMAIN profiles over the one engine (WEB, CODEREVIEW, custom)
  reflect.py        consolidation: hypothesis nodes, portrait summaries, SAME_AS
  embeddings.py     optional semantic vectors (dependency-free hashing fallback)
  mcp_server.py     MCP server (Claude Desktop / Claude Code) exposing the facade
skills/code-review/SKILL.md   the memory-driven code-review method for Claude
docs/CODE_REVIEW_INTEGRATION.md  setup for Claude Desktop + Claude Code CLI
  research.py       revision-aware research-evidence memory (ResearchMemory):
                    snapshots, scoped value identities, EXPLICIT flow edges,
                    guards, evidence/hypothesis/validation/finding lifecycle,
                    consensus, append-only reclassification, SQL-side retrieval
  research_tools.py MCP contract layer: stable error codes, idempotency, validation
  research_mcp.py   Firefox research MCP server (stdio; thin transport over tools)
  schema_research.sql / schema_firefox.sql   v2 / v3 research + Firefox tables
  migrations.py     schema_version + additive forward migrations (refuses newer)
  artifacts.py      immutable content-addressed artifact store (SHA-256, atomic)
  backup.py         backup / restore / verify (metadata DB + artifacts, by digest)
tests/              stdlib unittest (110 tests; web + research/Firefox evidence)
examples/demo.py              web exploit-chain demo
examples/codereview_demo.py   code-review taint-chain demo (same engine)
benchmarks/bench_retrieval.py reproducible retrieval benchmark (1k/10k/50k)
```

## Any domain, one engine (profiles)

The engine (store, chains, capability unification, retrieval, forgetting,
persistence, security) is **domain-agnostic**. A `Profile` supplies only the
domain knowledge: the capability ontology (what facts provide/require), the
escalation rules + goal severities, and how to label a node in a narrative.
Swapping the profile retargets the whole memory — same graph, same chain engine.

```python
from agentmem import Memory
from agentmem.profiles import CODEREVIEW          # or WEB (default), or your own Profile

m = Memory("repo.db", profile=CODEREVIEW)          # source-code taint analysis
m.add_taint_source("handlers/user.py", var="name", line=12)
m.add_taint_prop("handlers/user.py", var_in="name", var_out="query", line=15)
m.add_taint_sink("db/exec.py", var="query", sink_type="sql", line=40)
m.chains()   # -> taint_source -> taint_prop -> taint_sink ==> FULL_DB_READ
```

A data-flow vulnerability **is** a capability chain: a source `provides tainted{var}`,
a sink `requires tainted{var}`, and the path between them is found by the identical
unification engine that chains web findings. Because a codebase is far larger than a
context window, the graph + paging + retrieval is exactly what long-horizon code
review needs. Write a new `Profile` (ontology + labels) to add any other domain —
cloud/IaC audit, OSINT pivoting, SRE incident memory — on the same core.

## Honest scope

- This is the agent's **memory**, not the agent. It records and connects what the
  agent discovers; it does not itself send requests or confirm vulns.
- The **verification gate is only as good as the oracle you pass** — a finding is
  `confirmed` only when the agent provides concrete proof; otherwise it is
  `suspected` and produces `candidate` (not confirmed) chains.
- The capability **ontology is a curated starting set** (a `Profile`, see
  `profiles.py`) — extend the tokens/extractors/escalation rules per vuln class,
  or write a new `Profile` for a new domain.
- The secrets-vault cipher is **stdlib obfuscation-at-rest**, not a KMS — back it
  with real crypto (Fernet/KMS) for production; the interface is unchanged.
- For authorized testing only.

Design + provenance: `../docs/MEMORY_DESIGN.md` (the 28-paper synthesis spec).

## Hardening pass (applied)

A verified review pass fixed real correctness bugs and added robustness:
- **Status reconciliation** — a later confirmed observation now promotes a stored
  `suspected` node (and raises its trust); invalidated nodes stay invalidated
  unless re-confirmed by an oracle.
- **Retracted chains** — invalidating a step node now retracts any chain built on
  it (hidden by default, row preserved for audit) — a withdrawn critical finding
  can never surface as live.
- **Trust gate** — `target_derived` facts can never reach `confirmed`.
- **Correctness** — case-distinct paths no longer merge (`/Admin` ≠ `/admin`);
  the capability glob is case-insensitive and platform-independent; `next_probes`
  now covers single-need goals; duplicate "padded" chains are suppressed.
- **Performance** — detection is decoupled from writes (lazy, dirty-flagged);
  `PRAGMA synchronous=NORMAL`; batched retrieval touches; `store.transaction()`.
- **Security** — the sanitizer folds unicode (NFKC) and strips zero-width/bidi
  chars; the secrets vault takes an external key via `AGENTMEM_VAULT_KEY`.
- **Integration** — `Memory.context()` renders a token-budgeted, **secret-redacted**
  memory block for an LLM prompt; `stats()`, `get_secret()`, `redact()` added.

## Backlog pass (applied)

The previously-deferred items are now built and tested:
- **Consensus promotion + provenance** — observations attach to a finding
  (`obs_id`); `CONSENSUS_N` distinct corroborating observations promote a
  `suspected` finding to `confirmed` (weaker than an oracle); every node carries
  its supporting observation ids.
- **Persisted hypothesis nodes** — the backward-chaining next-probe queue is
  materialized as `hypothesis` nodes that survive restarts (`rehydrate` step 4)
  and auto-resolve once a live chain reaches their goal.
- **Portrait summaries** — a deterministic per-host structured summary (tech,
  endpoints, confirmed findings, chains), rebuilt on `reflect()`.
- **Semantic recall** — `Memory(embeddings=True)` enables a dependency-free
  hashing embedding; `recall(query="…")` fuses exact + graph + semantic via RRF;
  `reflect()` adds advisory `SAME_AS` synonym edges (never merges nodes).
- **Incremental chain detection** — ENABLES edges rebuild only for nodes changed
  since the last pass (full once, then incremental), off the write hot path.

## Still deferred (optional quality upgrades)

LLM-based summarization/narration and a real embedding model
(sentence-transformers) behind the existing interfaces — both strictly additive;
the deterministic, dependency-free core already covers every requirement.

## License
MIT.
