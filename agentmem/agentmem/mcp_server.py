"""
agentmem.mcp_server — expose agentmem as an MCP server for Claude Desktop / Claude Code.

This is the integration bridge. Claude (Desktop or the CLI) speaks the Model
Context Protocol; this process wraps a single persistent `agentmem.Memory` and
surfaces it as MCP tools. The agent reviews code (or a web target) over many
turns and many *sessions*: facts accumulate on disk in one SQLite file while the
model's context window stays small, because the heavy state lives here, not in
the transcript. The agent pulls only what it needs back via `recall` /
`get_context`, and the deterministic chain engine connects findings the model
saw turns — or days — apart.

Run it (stdio transport):

    AGENTMEM_DB=/path/telegram.db AGENTMEM_PROFILE=codereview \
        python -m agentmem.mcp_server

Configuration (environment variables):
    AGENTMEM_DB          path to the SQLite memory file   (default: ./agentmem.db)
    AGENTMEM_PROFILE     "codereview" | "web"             (default: web)
    AGENTMEM_EMBEDDINGS  "1"/"true" to enable semantic recall (default: off)

Registration commands and the Claude Desktop config block are in
docs/CODE_REVIEW_INTEGRATION.md.

Design notes:
  * One long-lived Memory instance, created lazily on first use. All tool bodies
    run under a single lock, so the SQLite connection (opened with
    check_same_thread=False) is only ever touched serially — safe whether the SDK
    runs tools on the event loop or offloads them to a thread pool.
  * Tools return plain strings (human-readable text, compact JSON where a
    structure helps). That is the correct, portable MCP tool return type — the
    model reads the text directly.
  * STDOUT IS THE TRANSPORT. Nothing may print to stdout except the protocol.
    We never print; any diagnostics go to stderr.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from typing import Optional

from . import profiles
from .memory import Memory

# --------------------------------------------------------------------------- #
# SDK import shim: mcp>=2 renamed FastMCP -> MCPServer; the decorator/run API is
# otherwise identical. Support both so a user's `pip install mcp` just works.
# --------------------------------------------------------------------------- #
try:                                                       # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:                                # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server      # type: ignore


_INSTRUCTIONS = (
    "Persistent, chain-finding memory for long-horizon source-code review (and web "
    "bug-bounty). Record what you discover as you read code — taint SOURCES (untrusted "
    "input), FLOWS (assignments/calls that carry a tainted value forward), SINKS "
    "(dangerous operations), and SANITIZERS — then call get_chains to see which "
    "source->...->sink data-flow paths reach a dangerous sink, and next_probes for the "
    "missing link that would complete a suspected chain. Memory persists across sessions, "
    "so review a large repo subsystem by subsystem without re-reading what you already "
    "mapped. Call get_context at the start of a session to reload what memory already knows."
)

mcp = _Server("agentmem", instructions=_INSTRUCTIONS)

_LOCK = threading.Lock()
_MEM: Optional[Memory] = None


def _profile():
    name = os.environ.get("AGENTMEM_PROFILE", "web").strip().lower()
    return profiles.get(name)


def _embeddings_enabled() -> bool:
    return os.environ.get("AGENTMEM_EMBEDDINGS", "").strip().lower() in ("1", "true", "yes", "on")


def _memory() -> Memory:
    """Lazily open the one persistent Memory (shared across all tool calls)."""
    global _MEM
    if _MEM is None:
        db = os.environ.get("AGENTMEM_DB", "agentmem.db")
        _MEM = Memory(db, profile=_profile(), embeddings=_embeddings_enabled(),
                      check_same_thread=False)
    return _MEM


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- #
# Code-review (taint) tools — meaningful under AGENTMEM_PROFILE=codereview
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Record a TAINT SOURCE: a point where untrusted/attacker-controlled input enters "
        "(a request param, argv, env var, deserialized field, file/network read, RPC arg). "
        "`var` is the tainted variable/expression name; `symbol` the enclosing function; "
        "`line` the line number. Returns the stored node id."
    )
)
def record_source(file: str, var: str, symbol: str = "", line: int = 0,
                  oracle: str = "untrusted input reaches this variable") -> str:
    with _LOCK:
        nid = _memory().add_taint_source(file, var=var, symbol=symbol, line=line, oracle=oracle)
        return f"recorded taint_source node {nid}: {var} @ {file}:{line} in {symbol or '?'}"


@mcp.tool(
    description=(
        "Record a TAINT FLOW (propagator): a statement that carries taint from one value to "
        "another — an assignment, string concat/format, a call that returns a value derived "
        "from a tainted arg, a field store. `var_in` is the tainted input, `var_out` the "
        "newly-tainted output. Chains are built by matching a flow's var_in to an upstream "
        "var_out/source var, so name variables consistently. Returns the stored node id."
    )
)
def record_flow(file: str, var_in: str, var_out: str, symbol: str = "", line: int = 0,
                oracle: str = "taint propagates var_in -> var_out") -> str:
    with _LOCK:
        nid = _memory().add_taint_prop(file, var_in=var_in, var_out=var_out,
                                       symbol=symbol, line=line, oracle=oracle)
        return f"recorded taint_prop node {nid}: {var_in} -> {var_out} @ {file}:{line}"


@mcp.tool(
    description=(
        "Record a TAINT SINK: a dangerous operation that is unsafe when it receives tainted "
        "data. `var` is the value flowing in; `sink_type` classifies the danger and decides "
        "the resulting goal severity. Valid sink_type values: exec, command, eval, "
        "deserialize, template, pickle (=> RCE); sql, nosql (=> full DB read); path, "
        "file_read, file_write, xxe (=> file access); ssrf, open_redirect, xss (=> web); "
        "ldap, log, header (=> injection); format_string, buffer, integer_overflow (=> memory "
        "corruption); crypto (=> weak crypto); auth (=> auth bypass); generic. Returns the node id."
    )
)
def record_sink(file: str, var: str, sink_type: str, symbol: str = "", line: int = 0,
                severity: int = 8, oracle: str = "tainted value reaches a dangerous sink") -> str:
    with _LOCK:
        nid = _memory().add_taint_sink(file, var=var, sink_type=sink_type, symbol=symbol,
                                       line=line, severity=severity, oracle=oracle)
        return f"recorded taint_sink node {nid}: {sink_type}({var}) @ {file}:{line}"


@mcp.tool(
    description=(
        "Record a SANITIZER/validator that neutralizes taint on a value (escaping, "
        "parameterized-query binding, an allow-list check, safe cast). A sanitizer is "
        "documentation only: it breaks a chain by the ABSENCE of a flow for the cleaned "
        "value, so after recording a sanitizer do NOT record a taint flow carrying that same "
        "value past this point. Returns the node id."
    )
)
def record_sanitizer(file: str, var: str, symbol: str = "", line: int = 0,
                     oracle: str = "value is sanitized here") -> str:
    with _LOCK:
        nid = _memory().add_taint_sanitizer(file, var=var, symbol=symbol, line=line, oracle=oracle)
        return (f"recorded taint_sanitizer node {nid}: {var} @ {file}:{line} "
                f"(do not record a flow carrying {var} past this point)")


# --------------------------------------------------------------------------- #
# Web bug-bounty tool — meaningful under AGENTMEM_PROFILE=web
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Record a web finding (web profile). `vuln_class` e.g. open_redirect, idor, ssrf, "
        "oauth_redirect, xss. `confirmed` only when you have a concrete oracle (proof); "
        "otherwise it is stored as suspected. `attrs_json` is an optional JSON object of "
        "capability attributes (e.g. {\"host\":\"app.target.com\"}) used for chain "
        "unification. Returns the node id."
    )
)
def record_finding(vuln_class: str, host: str = "", path: str = "/", param: str = "",
                   confirmed: bool = False, oracle: str = "", severity: int = 5,
                   attrs_json: str = "", obs_id: int = 0) -> str:
    attrs = json.loads(attrs_json) if attrs_json.strip() else None
    with _LOCK:
        nid = _memory().add_finding(vuln_class, host=host, path=path, param=param,
                                    confirmed=confirmed, oracle=oracle, severity=severity,
                                    attrs=attrs, obs_id=obs_id or None)
        state = "confirmed" if confirmed else "suspected"
        return f"recorded {state} finding node {nid}: {vuln_class} @ {host}{path} ({param})"


# --------------------------------------------------------------------------- #
# Profile-agnostic tools
# --------------------------------------------------------------------------- #
@mcp.tool(
    description=(
        "Log a raw observation (lossless episodic memory) — the evidence behind a fact: a "
        "code snippet you read, a diff hunk, an HTTP request/response, a tool output. "
        "`request` is the context/query, `response` the content. Returns an obs_id you may "
        "pass to record_finding for provenance. Negative evidence (something you checked and "
        "ruled out) is worth logging too."
    )
)
def observe(request: str, response: str = "", source: str = "code") -> str:
    with _LOCK:
        oid = _memory().observe(request, response, source=source)
        return f"logged observation {oid}"


@mcp.tool(
    description=(
        "Return the discovered chains — data-flow paths (code review) or exploit chains "
        "(web) where one fact's capability enables the next, terminating at a dangerous "
        "goal. Highest severity first, each with its cited steps and a narrative. This is "
        "the payoff: call it after recording sources/flows/sinks to see which reach a sink. "
        "Confirmed-only chains unless a step is still suspected (then a candidate chain)."
    )
)
def get_chains(include_invalidated: bool = False) -> str:
    with _LOCK:
        chains = _memory().chains(include_invalidated=include_invalidated)
    if not chains:
        return ("no chains yet — record more taint flows/sinks, or a source and sink are not "
                "yet connected (see next_probes for the missing link).")
    lines = [f"{len(chains)} chain(s):"]
    for c in chains:
        lines.append(f"\n[sev {c['severity']}] {c['goal']}  ({c['status']})")
        lines.append(f"  {c['narrative']}")
        for i, s in enumerate(c["steps"]):
            loc = f" {s['host']}{s['path']}".rstrip() if (s.get("host") or s.get("path")) else ""
            lines.append(f"    {i+1}. node {s['node_id']}: {s['label']}{loc}")
    return "\n".join(lines)


@mcp.tool(
    description=(
        "Goal-directed backward chaining: the missing capabilities that would COMPLETE a "
        "suspected chain. In code review this tells you what to look for next — e.g. 'a flow "
        "carrying `query` into a sql sink', so you know which call path to trace rather than "
        "reading the whole repo. Returns a ranked list of probes toward the highest-value goals."
    )
)
def next_probes() -> str:
    with _LOCK:
        probes = _memory().next_probes()
    if not probes:
        return "no open probes — no suspected chain is one step from a goal."
    return _dumps(probes)


@mcp.tool(
    description=(
        "Ranked recall from memory. Filter by `type` (e.g. finding, taint_source, taint_sink, "
        "endpoint, credential), and/or pass a free-text `query` for semantic matching (only "
        "when AGENTMEM_EMBEDDINGS is enabled). Use this to check what you already know about "
        "a file/function before re-reading it. Returns up to `limit` ranked hits as JSON."
    )
)
def recall(query: str = "", type: str = "", host: str = "", vuln_class: str = "",
           limit: int = 20) -> str:
    with _LOCK:
        hits = _memory().recall(type=type or None, host=host or None,
                                vuln_class=vuln_class or None, limit=limit,
                                query=query or None)
    return _dumps(hits) if hits else "no matching memory."


@mcp.tool(
    description=(
        "Return a compact, secret-redacted MEMORY BLOCK to orient yourself: the target, the "
        "highest-value known chains, pinned/high-severity facts, and open hypotheses, "
        "truncated to `budget_chars`. Call this at the START of a review session (or when "
        "resuming) to reload what memory already knows without spending context on the full "
        "store. This is the primary 'what do I already know' call."
    )
)
def get_context(budget_chars: int = 4000) -> str:
    with _LOCK:
        return _memory().context(budget_chars=budget_chars)


@mcp.tool(
    description=(
        "Consolidation pass (call occasionally, e.g. after finishing a subsystem): re-detect "
        "all chains, pin verified assets so they are never forgotten, persist the next-probe "
        "queue as hypotheses that survive restarts, and rebuild per-file/host portrait "
        "summaries. Returns counts."
    )
)
def reflect() -> str:
    with _LOCK:
        return _dumps(_memory().reflect())


@mcp.tool(
    description=(
        "Retract a fact you now believe is wrong (a false-positive source/sink, a flow that "
        "does not actually propagate). Soft-invalidates the node (kept for audit) and "
        "retracts any chain built on it, so a withdrawn finding can never resurface. Pass the "
        "node id (from a record_* or get_chains result) and a short reason."
    )
)
def invalidate(node_id: int, reason: str = "") -> str:
    with _LOCK:
        _memory().invalidate(node_id, reason=reason)
        return f"invalidated node {node_id}" + (f": {reason}" if reason else "")


@mcp.tool(
    description=(
        "Read-only health snapshot of the memory store: node counts by type, invalidated "
        "count, number of observations, live chain count, and the on-disk size in bytes. "
        "Cheap; runs no detection. Useful to confirm the memory is growing and the DB path "
        "is the one you expect."
    )
)
def stats() -> str:
    with _LOCK:
        s = _memory().stats()
        s["db_path"] = os.path.abspath(_memory().store.path)
        s["profile"] = _profile().name
    return _dumps(s)


def main() -> None:
    # Fail loud on stderr (never stdout) if misconfigured, then serve over stdio.
    print(f"[agentmem] profile={_profile().name} db={os.environ.get('AGENTMEM_DB', 'agentmem.db')} "
          f"embeddings={_embeddings_enabled()}", file=sys.stderr, flush=True)
    mcp.run()          # stdio transport by default


if __name__ == "__main__":
    main()
