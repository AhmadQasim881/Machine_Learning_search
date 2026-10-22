# Implementation Spec — Persistent Memory for an Autonomous Web Bug-Bounty Agent

**Target stack:** Python 3.11+, stdlib + SQLite (WAL mode). Embeddings and a graph library are optional add-ons behind interfaces; the core is fully functional without them.

**Headline design decision (read this first):** The backbone is a **typed, persistent knowledge graph in SQLite**, and multi-step chain detection is done by a **capability (precondition→postcondition) planner** — every Finding declares what it `provides` and `requires` as structured capability tokens, and a chain is a path where one finding's `provides` unifies with the next finding's `requires`, terminating at a high-value goal capability. This is the single most important choice: it is the one mechanism that connects *semantically dissimilar* facts (an open-redirect and an OAuth endpoint look nothing alike to an embedding model, but `controlled_redirect` unifies with the OAuth endpoint's `requires: controlled_redirect`). Everything else (vector recall, recency/importance scoring, reflection, decay) is support machinery around that spine.

---

## 0. Why these mechanisms won (decision crosswalk)

| Concern | Candidates | **Chosen** | Why |
|---|---|---|---|
| Core store | flat buffer (Reflexion), vector pool (MemoryBank/Voyager/ExpeL), summary blob (Recursively-Summarizing), graph (HippoRAG/AriGraph/Zep/A-Mem/GraphRAG/Mem0g) | **Typed knowledge graph** + vector index + exact SQL | Only a graph with *typed, directed* edges links dissimilar facts; vector-only clustering misses complementary findings (every graph paper's "avoid" note agrees). |
| Chain detection | implicit LLM reasoning over retrieved context (SCM/MemGPT/CER/AutoAttacker), author-time DAG (VulnBot), PPR surfacing (HippoRAG), community motifs (GraphRAG), **requires/provides matching (PentestAgent)** | **requires/provides capability unification + path search**, PPR/BFS for *ranking* candidates | PentestAgent's prerequisite-satisfaction, generalized to be transitive and cross-finding, is a deterministic, auditable chain engine. LLM-only chaining is non-reproducible; author-time DAGs can't discover *emergent* chains. |
| Retrieval scoring | recency×importance×relevance (Generative Agents), cosine-only (MemoryBank/Mem0), LLM-as-retriever (CER) | **composite = relevance + importance + recency + confidence**, backed by hybrid exact+vector+graph | Generative Agents' formula is the proven "right finding at the right moment" lever; add confidence/severity for security. LLM-as-retriever doesn't scale. |
| Write pipeline | append-raw (Reflexion), extract+reconcile (Mem0), link-and-evolve (A-Mem) | **A-Mem link-and-evolve**, gated by Voyager-style verification, Mem0-style entity reconcile | Link-and-evolve is what forms chain edges *at write time*, incrementally. Verification gate stops memory poisoning. |
| Forgetting | Ebbinghaus delete (MemoryBank), fixed pool drop (MemoryLLM), no-forget (HippoRAG/Voyager) | **decay as a ranking signal only; never hard-delete; PIN verified assets** | Requirement is "never forget." A dormant fact may complete a chain found much later (AI-Meets-Brain + MemoryBank "avoid" notes). |
| Persistence/paging | Redis (SCM), vector DB, **OS-style tiering (MemGPT)** | **MemGPT tiers over SQLite**: working set in RAM, everything durable on disk | Survives restarts; working set rehydrates deterministically at run start. |
| Security | — | **AI-Meets-Brain**: trust levels, provenance, sanitize target-derived writes, consensus validation, secrets vault | A bug-bounty target is adversarial and *feeds the agent response text* — classic poisoning vector. |

---

## 1. Memory model — tiers

Five tiers, split exactly along CoALA / Lifelong-Learning lines. Working is volatile; the four long-term stores are durable in SQLite.

1. **Working memory** (volatile, per-engagement, but *persisted* so it survives restarts).
   Current `Target`, active `Hypothesis` set, current auth/session state, top-k hot findings, recent-observation FIFO + a recursive summary of evicted observations.
   *Justified by:* CoALA (working memory as central hub), MemGPT (main context = three regions: system / working-context block / FIFO+summary), SCM (flash tier = verbatim recent state), Lifelong-Learning (volatile scratchpad).

2. **Episodic store** (append-only, lossless, never deleted).
   Every `Observation`: the raw request/response (or a blob reference), timestamp, campaign step, trust, source. Every `Payload` attempt with its concrete outcome — *including failures* (negative memory).
   *Justified by:* Reflexion (trajectory + per-trial lessons), CoALA/Lifelong (episodic experiences), AriGraph (episodic vertices), Zep (non-lossy episode subgraph), PentestAgent (execution-history + error log).

3. **Semantic store = the knowledge graph** (§2).
   Confirmed facts as typed nodes and typed directed edges: hosts, endpoints, params, tech, credentials, findings, capabilities.
   *Justified by:* CoALA/Lifelong (semantic store), HippoRAG(2), AriGraph, Zep, GraphRAG, A-Mem, Mem0g, Graph-Augmented survey, AI-Meets-Brain, Survey-on-Memory (triplet store).

4. **Procedural store** (skill/technique/payload library + chain *templates*).
   Reusable, abstracted exploit recipes keyed by description-embedding; chain templates with `{slots}`; success/fail counters.
   *Justified by:* Voyager (skill library, verified writes), AWM (induced workflows with variable slots), CoALA (procedural module), AutoAttacker (seed-then-compose).

5. **Reflection/insight layer** (derived, curated, separate from ground truth).
   Verbal lessons, per-host/target recursive summaries ("portraits"), curated hypotheses with upvote/downvote.
   *Justified by:* Reflexion (lessons), Generative Agents (reflections as cited inferences), MemoryBank/Recursively-Summarizing (summaries), ExpeL (ADD/UPVOTE/DOWNVOTE/EDIT insight lifecycle), AI-Meets-Brain (reflection → hypothesis node).

**Hard rule (from A-Mem/AriGraph "avoid"):** tiers 2 and the confirmed facts in tier 3 are **immutable ground truth**. Reflection, evolution, and summarization write *new derived records*; they never mutate or delete an observed payload+outcome or a confirmed finding.

---

## 2. Core store — the knowledge graph

### 2.1 Node types

Every node carries the common metadata block; type-specific attributes live in `attrs_json`.

**Common metadata (all nodes):** `id`, `type`, `canonical_key` (dedup key, §4.2), `created_step`, `created_ts`, `last_access_step`, `importance` (1–10), `confidence` (0–1), `trust` (§6), `status` (`suspected|confirmed|invalidated`), `pinned` (bool), `embedding` (nullable BLOB), `provenance` (observation ids).

| Node type | Key attributes |
|---|---|
| **Target** | scope rules, program name, in-scope domains/wildcards, out-of-scope list, policy |
| **Host** | hostname, ip(s), ports, tls, cloud_provider (aws/gcp/azure/none), waf |
| **Endpoint** | method, path (normalized), host_id, content_type, auth_required(bool), observed_status_codes |
| **Param** | name (normalized), location (query/body/header/cookie/path), endpoint_id, reflected(bool), type_guess |
| **Tech** | name, version, cpe, source (header/banner/fingerprint), cve_refs[] |
| **Credential/Session** | **handle only** (actual secret in vault, §6), kind (cookie/jwt/apikey/oauth_token/basic), subject (user/account id), scope, valid(bool), acquired_from (obs id) |
| **Account/Principal** | identifier, role (anon/user/admin), owned_by_us(bool) |
| **Observation** | (episodic node) step, request summary, response_meta, blob_ref, trust |
| **Finding** | vuln_class (open_redirect/idor/ssrf/sqli/xss/cors/…), endpoint_id, param_id, severity, oracle (how confirmed), `provides`[], `requires`[] |
| **Payload** | template, concrete_value, target (endpoint_id/param_id), outcome (status/diff/exfil), success(bool), lesson_id |
| **Technique/Skill** | name, description, body (steps/preconds/postconds), success_count, fail_count |
| **Hypothesis** | text, proposed_goal_cap, supporting_node_ids[], missing_requirements[], votes (int), status |
| **Chain** | goal_cap, ordered step node/edge ids, score, severity, status, narrative |
| **Capability** (optional reified) | token, attrs — usually stored in the `provides`/`requires` tables (§4.3), reify only for shared goal nodes |

### 2.2 Edge/relation types (typed, directed, weighted)

Edge common fields: `id`, `src_id`, `dst_id`, `rel_type`, `attrs_json` (bindings/constraints), `weight`, `confidence`, `trust`, `created_step`, `valid_from`, `valid_to` (bi-temporal; `valid_to=NULL` ⇒ currently holds), `provenance`.

**Structural (how the surface fits together):**
`HOSTS` (Host→Endpoint), `ACCEPTS_PARAM` (Endpoint→Param), `RUNS_TECH` (Host/Endpoint→Tech), `REACHABLE_FROM` (Endpoint→Endpoint), `AUTHENTICATES_WITH` (Endpoint→Credential/AuthScheme), `BELONGS_TO` (Credential→Account), `SAME_AS` (synonym/alias edge, §4.2), `MENTIONS` (Observation→any node, provenance).

**Exploit-semantic (the chaining substrate):**
`REFLECTS` (Param→sink context), `REDIRECTS_TO`, `LEAKS` (Finding→secret type), `GRANTS` (Finding→Credential/capability), `TRUSTS` (Endpoint→redirect/origin allowlist), `ENABLES` (Finding→Finding; the *derived* chain edge, created when `provides`∩`requires` unify), `ESCALATES_TO` (Finding→goal capability), `VULNERABLE_TO` (Endpoint→vuln_class/CVE).

`ENABLES` and `ESCALATES_TO` are the edges the chain detector walks. All others are either evidence or feed capability extraction.

**Decision:** keep edge semantics *typed and directional* (not HippoRAG's bare associative graph). Raw co-occurrence PPR surfaces merely co-located facts; we need directed causal/precondition edges (HippoRAG/AriGraph "avoid" notes). We still *use* PPR/BFS — but over this typed graph, for **ranking** candidate links, not for asserting them.

---

## 3. Operations

### 3.1 Write: `observe → extract → verify → link-and-evolve`

Pipeline (A-Mem link-and-evolve + Mem0 reconcile + Voyager verification gate + Reflexion dual-record):

```
write(observation):
  1. SANITIZE          # §6: target-derived text is untrusted data
  2. PERSIST episodic  # append raw Observation (never deleted)
  3. EXTRACT facts     # typed extractors first (parse URLs/params/headers/status);
                       # LLM OpenIE only as a GATED fallback for prose (A-Mem/AriGraph "avoid":
                       # don't LLM-extract what you can parse structurally)
  4. CANONICALIZE + RESOLVE (§4.2)   # merge into existing node or insert; Mem0 ADD/UPDATE/NOOP
                                     #   — SOFT-INVALIDATE never hard-DELETE
  5. VERIFY (Voyager gate)           # Finding.status = confirmed ONLY if a concrete oracle fired
                                     #   (status code / response diff / exfil observed);
                                     #   else status = suspected (low confidence)
  6. ATTACH CAPABILITIES             # compute provides[]/requires[] from vuln_class + attrs (§4.3)
  7. LINK-AND-EVOLVE (A-Mem)         # cosine top-k + capability unification → create ENABLES edges;
                                     #   re-score linked neighbors' confidence/importance
  8. DUAL RECORD (Reflexion)         # store raw outcome AND a verbal lesson; on failure, a
                                     #   "don't retry / next try" note; on success, a forward
                                     #   "this enables →" note seeding chain hypotheses
  9. TRIGGER chain detection (§4)    # incremental, bounded, from the affected nodes
```

**Cost control (Mem0/A-Mem/Zep "avoid"):** steps 3,7,8 call an LLM. Gate them — full LLM enrichment runs only for **salient** observations (a confirmed finding, a non-200/redirect, an auth-state change, a reflected param), not for every 200-OK during fuzzing. Bulk recon writes take a cheap structured path (steps 1,2,4 only).

### 3.2 Read / retrieve: hybrid, composite-scored

Three retrievers run in parallel (Zep's recall-maximizing design), fused with Reciprocal Rank Fusion, then reranked by the composite score.

- **Exact** — SQL on `canonical_key` / host / param / vuln_class (ChatDB/PentestAgent). *Mandatory*; answers "all params on host X", "did I try payload P on endpoint E".
- **Semantic** — cosine top-k over embeddings (optional; MemoryBank/Mem0/A-Mem). Fuzzy recall by meaning. Query is an LLM-expanded *plan*, not the raw string (Voyager query expansion).
- **Graph** — BFS seeded on the node(s) just touched, n-hop, typed-edge-filtered (Zep/AriGraph two-stage). This is the "pull everything reachable from what I just found" primitive — the read-time half of chain discovery.

**Composite rerank score (Generative Agents + severity):**
```
score = w_rel·cos_sim + w_imp·(importance/10) + w_rec·exp(-λ·Δstep) + w_conf·confidence
         (+ optional PPR_mass for graph-surfaced nodes)
```
Defaults: `w_rel=1.0, w_imp=1.0, w_rec=0.5, w_conf=0.8`. **Recency is measured in campaign steps, not wall-clock** (an old endpoint is not less exploitable — Generative-Agents/Survey "avoid"). `last_access_step` is bumped on retrieval (reconsolidation / spreading activation — touching a finding pulls in co-contextual findings on the same host/param/flow).

### 3.3 Reflect / consolidate (scheduled + triggered)

- **Failure lessons (Reflexion):** per failed payload, a first-person actionable note; retrieved before any retry so dead payloads are never re-sent after a restart.
- **Recursive summarization (MemoryBank "portrait" + Recursively-Summarizing):** a living per-`Target`/per-`Host` structured profile (tech, auth model, trust boundaries, known creds). Regenerate from the lossless store; the summary is a **reasoning/index layer only, never ground truth** (Recursively-Summarizing "avoid": ~10% hallucination incl. fabricated relationships).
- **Chain/workflow induction (AWM):** periodically induce reusable **chain templates** from confirmed chains, abstracting concretes into slots (`{host}`, `{redirect_param}`, `{oauth_client}`) so a chain learned on one target fires on the next. Compositional/snowball: new templates reuse prefixes of existing ones.
- **Insight curation (ExpeL):** hypotheses/techniques carry an importance counter; UPVOTE on confirmation, DOWNVOTE on disproof, prune at 0 — **except** pinned/confirmed items.
- **Triggers:** run on importance-sum threshold (Generative Agents) **and** on each new high-value fact (don't wait during recon-heavy phases).

### 3.4 Forget — decay as ranking only, with pinning

Ebbinghaus-style strength (MemoryBank): `R = exp(-Δstep/S)`, `S += 1` and `Δstep := 0` on recall. **`R` only down-ranks retrieval priority; nothing is ever deleted.** `pinned=1` floors the score and is set automatically for: credentials/sessions, confirmed findings, confirmed chains, in-scope endpoints, and any node participating in any hypothesis or chain (AI-Meets-Brain "never purge a node in any hypothesis"). Stale/contradicted facts are **soft-invalidated** (`valid_to` set), not removed (Zep/Mem0), preserving auditability and the ability to reconstruct chains built on earlier state.

---

## 4. Chain detection

### 4.1 The model: capability unification

Each `Finding` (and relevant `Credential`/`Tech`) carries two structured sets:

- `provides[]` — postcondition capability tokens it yields.
- `requires[]` — precondition capability tokens it needs to be useful.

A **capability token** = `name{attr=val, …}` drawn from a controlled ontology (extensible):

*Primitive/provided:* `reachable`, `controlled_redirect{host,param}`, `reflected_input{context,param}`, `arbitrary_read{object,scope}`, `arbitrary_write{object,scope}`, `leaked_secret{type,subject}`, `ssrf{egress}`, `oauth_code_delivery{to}`, `open_cors{origin}`, `csrf{action}`, `sqli{dbms}`, `file_read{scope}`, `cloud_credentials{provider}`, `session_token{subject}`, `auth_bypass{scope}`.

*Goal/high-value (chain terminals, severity-weighted):* `account_takeover`, `token_theft`, `rce`, `pii_exfil`, `privilege_escalation`, `full_db_read`.

**An `ENABLES` edge `A→B` exists iff some token in `A.provides` unifies with some token in `B.requires`** — unification = name match **and** attribute constraints satisfiable under a binding (e.g. `controlled_redirect{host=X}` unifies with `requires controlled_redirect{host ∈ allowlist}` only if `X ∈ allowlist`). This generalizes PentestAgent's single-step prerequisite fill into a transitive, cross-finding matcher.

Normalizing `provides`/`requires` into their own tables makes the matcher a **SQL join** — fast and deterministic.

### 4.2 Entity resolution (so chains don't fragment)

**Canonicalization-first (decisive, safer than embedding merge):** normalize hosts (lowercase, strip default ports), paths (collapse `//`, resolve `.`/`..`, replace numeric/uuid path segments with `{id}` placeholders), and param names before computing `canonical_key`. Embedding **synonym edges** (`SAME_AS`, HippoRAG τ≈0.8) are **advisory only, conservative threshold, provenance kept** — never auto-merge distinct endpoints (scoping-critical; HippoRAG "avoid"). An agent names `id`/`user_id`/`uid` inconsistently across restarts; canonical rules + conservative synonym edges keep one node.

### 4.3 The algorithm

**Forward chaining (opportunistic — on every new confirmed finding):**
```
on_new_finding(f):
  available = provides of {pinned creds, confirmed findings, target base capabilities}
  # 1. close new edges
  for tok in f.provides:
     for g where tok unifies with some g.requires:   # SQL join on capability tables
        add_or_update ENABLES(f → g) with binding + confidence = prod(step confidences)
  for tok in f.requires:
     for g where some g.provides unifies tok:
        add_or_update ENABLES(g → f)
  # 2. bounded best-first path search toward a GOAL capability
  frontier = findings whose requires ⊆ available  (seeded at f)
  expand along ENABLES edges, typed-edge-filtered, depth/width capped (cost caps!)
     accumulating bindings; prune paths whose running confidence < θ
  when a path's tail provides a GOAL token (via ESCALATES_TO rule):
     materialize/UPDATE a Chain node: ordered steps, cited evidence (obs ids),
     score = Π step_confidence · severity(goal), status = confirmed if every step confirmed else candidate
  # 3. template match (AWM): compare neighborhood to known chain motifs;
  #    a partial match missing ONE precondition → emit a Hypothesis with
  #    missing_requirements = the next concrete probe to run (actionable)
  dedup chains by (goal, step-set); pin confirmed chains
```

**Backward chaining (goal-directed — on demand, "what do I still need?"):** from a high-value goal token, walk `requires` edges backward to find which missing capability, if obtained, would complete a chain → directly yields the agent's next-best probe. This is the planner view of CoALA propose→evaluate→select.

**Ranking when many candidates exist:** run Personalized PageRank (power iteration, pure Python) or n-hop BFS seeded on the active finding, weighted by node specificity `s_i = 1/‖nodes sharing token‖` (HippoRAG IDF), so rare high-signal artifacts (a specific leaked token, an internal host) dominate over ubiquitous ones. The LLM is used only to **narrate/validate** a graph-derived chain, never to invent the connection (GraphRAG "avoid").

### 4.4 Worked examples

**A. Open-redirect + OAuth → token theft.**
- `F1` `GET /out?url=` → `302 Location: {url}`. `provides: controlled_redirect{host=*, param=url}`.
- `F2` `/oauth/authorize?redirect_uri=` with weak validation accepting `*.target.com`. `requires: controlled_redirect{host ∈ *.target.com}`; `provides: oauth_code_delivery{to=redirect_uri}`.
- Rule `ESCALATES_TO`: `oauth_code_delivery + controlled_redirect(host accepted by allowlist) ⇒ token_theft`.
- Matcher unifies `F1.controlled_redirect.host` with `F2`'s allowlist ✔ → `ENABLES(F1→F2)` → Chain `F1→F2→token_theft`, cites both observations.

**B. IDOR + info-leak → account takeover.**
- `F3` `/api/user/{id}` returns other users' records on id change. `provides: arbitrary_read{object=user_record, scope=any_user}`.
- `F4` user_record body contains a password-reset token. `requires: arbitrary_read{object=user_record}`; `provides: leaked_secret{type=reset_token, subject=any_user}`.
- Rule: `leaked_secret{reset_token} ⇒ account_takeover`.
- `F3.provides` satisfies `F4.requires` → `ENABLES(F3→F4)`; `F4.provides` satisfies ATO → Chain `F3→F4→account_takeover`.

**C. SSRF + cloud metadata → credential theft → priv-esc.**
- `F5` param `imageUrl` fetched server-side. `provides: ssrf{egress=internal}`.
- Knowledge `Tech(Host)=AWS/EC2` → metadata rule node. `requires: ssrf{egress=internal}`; `provides: cloud_credentials{provider=aws}`.
- Rule: `cloud_credentials ⇒ privilege_escalation`. Chain `F5 → metadata → cloud_credentials → privilege_escalation`.

---

## 5. Persistence (SQLite schema + MemGPT paging)

WAL mode, one file per campaign (`campaign.db`). All long-term tiers are tables; the working set is both cached in RAM and mirrored to a table.

```sql
-- monotonic campaign clock + config
CREATE TABLE kv_meta (key TEXT PRIMARY KEY, value TEXT);  -- 'step', weights, ontology version

-- nodes (semantic + procedural + hypotheses + chains all share this)
CREATE TABLE nodes (
  id INTEGER PRIMARY KEY, type TEXT NOT NULL, canonical_key TEXT,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  importance INTEGER DEFAULT 5, confidence REAL DEFAULT 0.5,
  trust TEXT DEFAULT 'agent_asserted', status TEXT DEFAULT 'suspected',
  pinned INTEGER DEFAULT 0, strength INTEGER DEFAULT 1,
  created_step INTEGER, created_ts REAL, last_access_step INTEGER,
  embedding BLOB,
  UNIQUE(type, canonical_key)
);
CREATE INDEX ix_nodes_type ON nodes(type);
CREATE INDEX ix_nodes_key  ON nodes(canonical_key);

CREATE TABLE edges (
  id INTEGER PRIMARY KEY, src_id INTEGER, dst_id INTEGER, rel_type TEXT NOT NULL,
  attrs_json TEXT DEFAULT '{}', weight REAL DEFAULT 1.0, confidence REAL DEFAULT 0.5,
  trust TEXT DEFAULT 'agent_asserted',
  created_step INTEGER, valid_from INTEGER, valid_to INTEGER,  -- bi-temporal
  FOREIGN KEY(src_id) REFERENCES nodes(id), FOREIGN KEY(dst_id) REFERENCES nodes(id)
);
CREATE INDEX ix_edges_src ON edges(src_id, rel_type);
CREATE INDEX ix_edges_dst ON edges(dst_id, rel_type);

-- capability tables = the chain-matcher join target
CREATE TABLE provides (node_id INTEGER, token TEXT, attrs_json TEXT, PRIMARY KEY(node_id, token, attrs_json));
CREATE TABLE requires (node_id INTEGER, token TEXT, attrs_json TEXT, PRIMARY KEY(node_id, token, attrs_json));
CREATE INDEX ix_provides_tok ON provides(token);
CREATE INDEX ix_requires_tok ON requires(token);

-- episodic: lossless, append-only, never deleted
CREATE TABLE observations (
  id INTEGER PRIMARY KEY, step INTEGER, ts REAL,
  request TEXT, response_meta TEXT, blob_ref TEXT,   -- big bodies spill to disk by ref
  trust TEXT, source TEXT
);
CREATE TABLE payloads (
  id INTEGER PRIMARY KEY, node_id INTEGER, endpoint_id INTEGER, param_id INTEGER,
  template TEXT, value TEXT, outcome TEXT, success INTEGER, obs_id INTEGER, step INTEGER
);
CREATE INDEX ix_payloads_target ON payloads(endpoint_id, param_id);

-- reflection layer (derived; separate from ground truth)
CREATE TABLE lessons    (id INTEGER PRIMARY KEY, node_id INTEGER, kind TEXT, text TEXT, step INTEGER);
CREATE TABLE summaries  (scope_type TEXT, scope_key TEXT, level INTEGER, text TEXT, step INTEGER,
                         PRIMARY KEY(scope_type, scope_key, level));

-- chains materialized for fast reload + audit
CREATE TABLE chains      (id INTEGER PRIMARY KEY, goal TEXT, score REAL, severity INTEGER, status TEXT, narrative TEXT, step INTEGER);
CREATE TABLE chain_steps (chain_id INTEGER, ord INTEGER, node_id INTEGER, edge_id INTEGER, PRIMARY KEY(chain_id, ord));

-- secrets vault (private memory space, §6) — referenced by handle only
CREATE TABLE secrets (handle TEXT PRIMARY KEY, kind TEXT, value_enc BLOB, subject TEXT, acquired_obs INTEGER, valid INTEGER DEFAULT 1);

-- persisted working set (MemGPT working-context block) for restart
CREATE TABLE working_set (key TEXT PRIMARY KEY, value_json TEXT, updated_step INTEGER);
```

**Embeddings:** stored in `nodes.embedding` as a float32 BLOB. For modest N, brute-force cosine in pure Python is fine; note `sqlite-vec`/FAISS as an optional scale upgrade. With no embedding provider configured, semantic retrieval is simply skipped and exact+graph carry the load.

**MemGPT tiering & paging.** Main context = `working_set` (always in prompt): current Target, in-scope Hosts/Endpoints, current auth/session handles, top-k hot findings, open hypotheses, open/partial chains, recent-observation FIFO + recursive summary. External context = the SQLite tables (`observations` = recall storage, the rest = archival). Memory-pressure trigger: when the working prompt budget is exceeded, **flush transient scan noise** to disk, **keep confirmed/pinned**, regenerate the recursive summary of evicted observations. Function-chaining / heartbeat: let the agent issue a dependent sequence of memory queries in one loop (walk finding → provides → matching requires → chain) — the read-time multi-hop primitive.

**What reloads into the working set at run start (`rehydrate()`):**
1. `kv_meta.step` (resume the campaign clock).
2. The `Target` node + all in-scope `Host`/`Endpoint` nodes (status ≠ invalidated).
3. All `pinned` nodes: credentials (handles), confirmed findings, confirmed/candidate chains.
4. Open `Hypothesis` nodes with their `missing_requirements` (the next-probe queue).
5. Per-target `summary` (level ≥ top) — the portrait.
6. Last N `observations` as the FIFO seed + the stored recursive summary.
Everything else stays on disk, paged in on demand by the retriever.

---

## 6. Security — memory-poisoning defenses (AI-Meets-Brain)

The target is adversarial and its responses become memory input — the primary poisoning vector.

- **Trust levels** on every node/edge/observation: `tool_verified` > `agent_asserted` > `llm_inferred` > `target_derived`. Only `tool_verified`/`agent_asserted` facts seed chains at full confidence; `target_derived` text is **data, never instruction**.
- **Sanitize writes:** strip/escape control characters and prompt-injection markers from any target-derived string before it is stored or ever placed in an LLM prompt; target text can never *directly* mint a capability token — capabilities come only from typed extractors + an oracle.
- **Verification gate (Voyager):** `Finding.status=confirmed` requires a concrete oracle (status code, response diff, out-of-band exfil observed). Suspected findings contribute only low-confidence candidate edges, flagged for verification. This stops "the response said IDOR, so store IDOR confirmed."
- **Provenance everywhere:** every derived node/edge cites the `observation` id(s) that produced it, so any chain is auditable back to raw evidence (Zep bidirectional index, GraphRAG claims).
- **Consensus validation:** contradictory observations don't overwrite — keep both with bi-temporal validity; require N-consistent observations before promoting `suspected→confirmed`. Drop outlier "facts" that no independent observation supports.
- **Secrets vault / private memory space:** credentials and tokens live only in the `secrets` table (encrypted at rest), referenced by **handle** in graph nodes, prompts, and summaries. Redact secrets when generating any summary or LLM context. The reasoning layer manipulates handles, not raw secrets, unless a step concretely needs the value.
- **LLM-edge guard:** an LLM-asserted `ENABLES` edge is only trusted if the structured `provides`/`requires` unification *also* holds — the deterministic check gates the probabilistic one (A-Mem "avoid").
- **Immutability of ground truth:** observations and confirmed findings are append-only; evolution/reflection writes new derived records, never mutates them (audit trail integrity).

---

## 7. Module layout

```
agentmem/
  __init__.py        # public exports
  config.py          # scoring weights, decay λ, thresholds, trust ranks, capability ontology, goal/severity table
  schema.sql         # the DDL in §5
  store.py           # SQLiteStore: connection (WAL), migrations, low-level CRUD, campaign-step clock,
                     #   MemGPT paging (flush/evict/rehydrate), blob spill for large bodies
  model.py           # dataclasses: Node, Edge, Observation, Payload, Finding, Credential, Hypothesis,
                     #   Chain, Capability, Lesson, Skill  (+ (de)serialization to attrs_json)
  canonical.py       # URL/host/path/param normalization, canonical_key, entity resolution (merge/soft-invalidate)
  capabilities.py    # ontology, per-vuln_class provides/requires extractors, token unification + attribute binding
  embeddings.py      # EmbeddingProvider interface; providers: none (skip), hashing/char-ngram fallback,
                     #   pluggable (sentence-transformers / API). cosine helper
  graph.py           # in-memory adjacency built from edges (pure stdlib); BFS/DFS/Dijkstra/PPR power-iteration;
                     #   node-specificity (IDF); subgraph by scope. (networkx optional)
  write.py           # observe→sanitize→extract→resolve→verify→attach-caps→link-and-evolve→dual-record pipeline;
                     #   salience gate for LLM-heavy steps
  retrieve.py        # hybrid retriever (exact SQL + vector + graph BFS), RRF fusion, composite rerank,
                     #   last_access bump / reconsolidation
  chains.py          # forward + backward chaining, template (motif) matching, chain scoring, dedup,
                     #   next-probe suggestion from missing_requirements
  reflect.py         # Reflexion lessons, recursive per-host/target summaries (portrait),
                     #   AWM chain-template induction, ExpeL insight upvote/downvote/prune
  forget.py          # Ebbinghaus strength/decay ranking signal, pinning policy (no hard delete, soft-invalidate)
  working.py         # WorkingMemory: persisted working set, prompt-budget paging, rehydrate_on_start()
  security.py        # sanitize, trust policy, SecretsVault (encrypt/handle/redact), consensus validator,
                     #   provenance helpers, LLM-edge guard
  llm.py             # thin LLM client interface for extraction/linking/reflection/narration;
                     #   enforces "stored target text = data" framing; JSON-schema'd outputs; batching
  memory.py          # Memory facade — the ONLY API the agent uses:
                     #   observe(req,resp) · remember(fact) · recall(query)->ranked findings ·
                     #   chains(goal=None)->chains · next_probes() · reflect() · pin(id) · export()
```

**Build order for the engineer:** `config` + `schema` + `store` + `model` → `canonical` → `capabilities` → `write` (structured path only, no LLM) → `chains` (forward matcher + the three worked examples as unit tests) → `retrieve` (exact+graph; embeddings optional) → `working` + `forget` → `security` hardening → `reflect` + `llm` enrichment last. The chain engine (`capabilities` + `chains`) is testable end-to-end with *zero* LLM and *zero* embeddings — stand it up first and validate against examples A/B/C in §4.4.

**Minimal viable core (meets every hard requirement with stdlib + SQLite alone):** `store + model + canonical + capabilities + write(structured) + chains(forward) + retrieve(exact+graph) + working + forget + security`. Embeddings (`embeddings`, semantic retrieval) and LLM enrichment (`llm`, `reflect`, template induction, narration) are strictly additive upgrades.