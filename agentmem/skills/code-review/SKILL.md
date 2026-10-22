---
name: memory-driven-code-review
description: >-
  Source-code security review that remembers across a whole repository and across
  sessions. Use when reviewing a large codebase (e.g. a messenger, a server, an SDK)
  for injection / RCE / auth / memory-safety bugs and you want findings to accumulate
  as data-flow (taint) facts in a persistent store, so the agent's context stays small
  while memory grows — and multi-step source->...->sink chains are found automatically.
  Requires the `agentmem` MCP server (profile=codereview). Setup:
  agentmem/docs/CODE_REVIEW_INTEGRATION.md.
---

# Memory-driven code review

You are reviewing source code for security vulnerabilities over many files and
many sessions — far more than fits in one context window. You have an `agentmem`
MCP server configured with the **codereview** profile. It is your long-term
memory: it holds what you have discovered on disk and connects facts you recorded
turns — or days — apart into **data-flow (taint) chains** that reach a dangerous
sink. Your job is to *feed it structured facts as you read code* and *ask it what
those facts add up to*, not to hold the whole program in your head.

## Mental model: record facts, let memory find the chains

A vulnerability is a path: **untrusted input (source) → it flows through code
(flows) → it reaches a dangerous operation (sink)**, with no **sanitizer** on the
way. You do not have to see the whole path at once. Record each hop as you find
it; memory unifies them by variable name and reports the completed chain, even if
you saw the source today and the sink next week.

The payoff tools:
- **`get_chains`** — the source→…→sink paths that reach a dangerous goal. This is
  the finding list. Call it after recording facts for a subsystem.
- **`next_probes`** — the data-flow *gap* to trace next: a **dangling sink** (a
  dangerous call whose tainted origin you haven't found — trace backward), a
  **dangling source** (untrusted input you haven't followed to a sink — trace
  forward), or an **orphan flow**. This tells you where to spend your limited
  reading budget instead of re-reading the repo.

## The loop

1. **Orient (start of every session).** Call **`get_context`** first. It reloads,
   in a few hundred tokens, what memory already knows: the chains found so far,
   pinned high-value facts, and open hypotheses. Then call **`next_probes`** to
   get the highest-value gap to chase. Do NOT re-read files you have already
   mapped — check **`recall`** (by file/symbol/type) before opening a file again.

2. **Pick a subsystem** (an entry-point handler, a parser, an auth path, a
   serializer). Read it with the intent of finding the three roles below.

3. **Record as you read** — one tool call per fact, with precise `file`, `line`,
   `symbol`, and variable names:
   - `record_source(file, var, symbol, line)` — a value that enters from outside
     trust: a request/RPC parameter, `argv`, an env var, a deserialized field, a
     file/socket read, inbound message bytes.
   - `record_flow(file, var_in, var_out, symbol, line)` — a statement that carries
     taint forward: assignment, string concat/format, a call whose return derives
     from a tainted argument, a struct/field store. **`var_in` must match the
     upstream `var_out`/source `var`** — that name match is how chains link, so be
     consistent (rename deliberately when the code does).
   - `record_sink(file, var, sink_type, symbol, line)` — a dangerous operation,
     unsafe with tainted input. Pick `sink_type` from the table below; it sets the
     severity.
   - `record_sanitizer(file, var, symbol, line)` — escaping, parameterized-query
     binding, an allow-list/type check, a safe cast. A sanitizer breaks the chain
     **by absence**: after recording it, do NOT record a flow that carries that
     same cleaned value onward. (If you are unsure the sanitizer is complete, model
     it as a flow instead and let the chain surface for manual judgement.)
   - `observe(request, response)` — optionally log the raw snippet/diff behind a
     fact for the audit trail.

4. **Ask what it means.** Call **`get_chains`**. Each chain is a candidate finding
   with cited steps (file:line for every hop) and a goal + severity. Then
   **`next_probes`** again for the next gap.

5. **Consolidate.** After finishing a subsystem, call **`reflect`** — it pins
   verified assets so they are never forgotten, persists the open gaps as
   hypotheses that survive a restart, and rebuilds per-file summaries.

6. **Prune false positives.** If you conclude a recorded source/sink/flow is wrong
   (not actually attacker-controlled, or sanitized upstream), call
   **`invalidate(node_id, reason)`**. The node is kept for audit and any chain
   built on it is retracted, so a withdrawn finding can never resurface.

## `sink_type` → goal (severity)

| sink_type | example | goal | sev |
|---|---|---|---|
| `exec`, `command`, `eval`, `deserialize`, `template`, `pickle` | `os.system`, `eval`, `yaml.load`, SSTI, `pickle.loads` | rce | 10 |
| `format_string`, `buffer`, `integer_overflow` | `printf(user)`, `memcpy`, size math | memory_corruption | 9 |
| `sql`, `nosql` | string-built query, `$where` | full_db_read | 9 |
| `file_write` | write to a user-named path | file_write | 8 |
| `auth` | auth/authz decision on tainted data | auth_bypass | 8 |
| `ssrf` | server-side fetch of a user URL | ssrf_exec | 7 |
| `path`, `file_read`, `xxe` | traversal, user-named read, XML entity | file_read | 7 |
| `xss` | unescaped value into HTML | xss_exec | 6 |
| `ldap`, `log`, `header` | LDAP filter, log/response-header injection | injection | 6 |
| `open_redirect` | redirect to a user-supplied URL | open_redirect | 5 |
| `crypto` | weak/misused primitive on sensitive data | weak_crypto | 5 |
| `generic` / anything else | unclassified dangerous call | injection | 6 |

## Discipline that keeps this efficient and correct

- **Memory holds state; your context stays small.** Record a fact, then move on —
  do not keep whole files in the transcript. Reload with `get_context`/`recall`
  when you need prior knowledge. This is what lets one review span a repo far
  larger than any context window, across restarts.
- **One DB per repository** (set `AGENTMEM_DB` per repo). Facts from different
  codebases must not mix.
- **Name variables the way the code does, consistently**, so flows unify. A chain
  is missed only when a `var_in` fails to match the upstream `var_out`.
- **Record negative results too** — a sink you checked and found safe, a source
  that is validated at the boundary — as an `observe` note or a sanitizer, so you
  don't re-investigate it next session.
- **A chain is a *candidate*, not a confirmed bug.** Before reporting, confirm the
  path is actually reachable (the branch is taken, the sanitizer really is absent
  or bypassable, the input really is attacker-controlled). `get_chains` gives you
  the exact file:line steps to verify.
- **Prefer `next_probes` over breadth.** Chase the highest-severity gap (a dangling
  `exec`/`sql`/`deserialize` sink) before mapping low-value code.

## Worked micro-example

Reviewing a message handler:
```
record_source(file="handlers/msg.py", var="text", symbol="on_message", line=20)
record_flow(file="handlers/msg.py", var_in="text", var_out="cmd", symbol="on_message", line=24)
record_sink(file="exec/shell.py", var="cmd", sink_type="command", symbol="run", line=8)
get_chains()
# -> [sev 10] rce: taint_source(on_message) @ handlers/msg.py:20
#      -> taint_prop @ handlers/msg.py:24 -> taint_sink(run) @ exec/shell.py:8  ==> RCE
```
If instead you had only found the sink:
```
record_sink(file="exec/shell.py", var="cmd", sink_type="command", symbol="run", line=8)
next_probes()
# -> [sev 10] rce: DANGLING SINK: command sink at exec/shell.py:8 consumes 'cmd',
#      but no tainted origin for 'cmd' is recorded. Trace 'cmd' backward ...
```
— which tells you exactly what to read next to close the gap.
