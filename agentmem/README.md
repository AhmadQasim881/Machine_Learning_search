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
python -m unittest discover -s tests        # 43 tests, stdlib only
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
tests/              stdlib unittest (43 tests; web chains + code-review taint chains)
examples/demo.py              web exploit-chain demo
examples/codereview_demo.py   code-review taint-chain demo (same engine)
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
