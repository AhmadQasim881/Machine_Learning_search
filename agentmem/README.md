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
python -m unittest discover -s tests        # 17 tests, stdlib only
python examples/demo.py                      # runs the 3 worked chain examples
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
tests/              stdlib unittest (17 tests; the 3 worked chains included)
examples/demo.py    runnable demonstration
```

## Honest scope

- This is the agent's **memory**, not the agent. It records and connects what the
  agent discovers; it does not itself send requests or confirm vulns.
- The **verification gate is only as good as the oracle you pass** — a finding is
  `confirmed` only when the agent provides concrete proof; otherwise it is
  `suspected` and produces `candidate` (not confirmed) chains.
- The capability **ontology is a curated starting set** (`config.py`) — extend the
  tokens/extractors/escalation rules as you cover more vuln classes.
- The secrets-vault cipher is **stdlib obfuscation-at-rest**, not a KMS — back it
  with real crypto (Fernet/KMS) for production; the interface is unchanged.
- For authorized testing only.

Design + provenance: `../docs/MEMORY_DESIGN.md` (the 28-paper synthesis spec).

## License
MIT.
