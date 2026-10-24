"""
agentmem.research_mcp — Firefox research MCP server (Claude Desktop / Claude Code).

A THIN adapter: transport only. Each tool forwards to agentmem.research_tools,
which owns validation, stable error codes, idempotency, and result bounding, which
in turn calls agentmem.research (storage). Storage/analysis logic never lives in
the transport layer. Tools return the structured envelope as JSON text.

Config (environment):
    AGENTMEM_DB      path to the SQLite research database (default ./research.db)
    AGENTMEM_ACTOR   actor id recorded in provenance/audit (default 'mcp')

Run (stdio):  AGENTMEM_DB=/path/firefox.db python -m agentmem.research_mcp

STDOUT IS THE TRANSPORT — diagnostics go to stderr only.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from typing import Optional

from .research import ResearchMemory
from .research_tools import ResearchTools

try:                                                       # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:                                # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server      # type: ignore

_INSTRUCTIONS = (
    "Revision-aware, evidence-based memory for authorized Firefox source-code security "
    "research. Register a repository snapshot first; every code fact is scoped to it. Record "
    "scoped value identities and EXPLICIT flow transitions (never rely on shared variable "
    "names), analysis evidence, hypotheses + counter-evidence, and validation runs. Use "
    "review_chain to see which transitions are demonstrated and which are missing, and "
    "query_history for revision-aware recall. Results are structured with stable error codes "
    "(INVALID_ARGUMENT, NOT_FOUND, REVISION_MISMATCH, STALE_EVIDENCE, CONFLICT, "
    "BACKEND_UNAVAILABLE, RESOURCE_LIMIT); mutations accept an idempotency_key.")

mcp = _Server("agentmem-firefox-research", instructions=_INSTRUCTIONS)
_LOCK = threading.Lock()
_TOOLS: Optional[ResearchTools] = None


def _tools() -> ResearchTools:
    global _TOOLS
    if _TOOLS is None:
        db = os.environ.get("AGENTMEM_DB", "research.db")
        actor = os.environ.get("AGENTMEM_ACTOR", "mcp")
        _TOOLS = ResearchTools(ResearchMemory(db, actor=actor, check_same_thread=False))
    return _TOOLS


def _j(envelope) -> str:
    return json.dumps(envelope, ensure_ascii=False, default=str)


@mcp.tool(description="Register (or return) a repository snapshot: repo_id + full commit_id, "
                      "optional dirty/patch_digest/scope. Every code fact references a snapshot.")
def register_repository_snapshot(repo_id: str, commit_id: str, dirty: bool = False,
                                 patch_digest: str = "", scope: str = "",
                                 idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().register_repository_snapshot(repo_id, commit_id, dirty, patch_digest,
                                                        scope, idempotency_key))


@mcp.tool(description="Record an exact, revision-scoped source reference (path is case-sensitive).")
def record_source_reference(snapshot_id: int, path: str, start_line: int = 0, end_line: int = 0,
                            symbol_id: str = "", language: str = "", excerpt: str = "",
                            idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_source_reference(snapshot_id, path, start_line, end_line,
                                                   symbol_id, language, excerpt or None,
                                                   idempotency_key))


@mcp.tool(description="Record a scoped value identity (a flow-graph node): path, value_name, role "
                      "(source|sink|transform|param|return|field|value), symbol, range, sink_type.")
def record_value_identity(snapshot_id: int, path: str, value_name: str, role: str = "value",
                          symbol_id: str = "", start_line: int = 0, end_line: int = 0,
                          sink_type: str = "", language: str = "", idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_value_identity(snapshot_id, path, value_name, role, symbol_id,
                                                 start_line, end_line, sink_type, language,
                                                 idempotency_key))


@mcp.tool(description="Record analysis evidence (raw bytes preserved as an immutable artifact; a "
                      "bounded redacted projection stored for search). status gated by trust.")
def record_analysis_evidence(snapshot_id: int, kind: str = "static_analysis", raw: str = "",
                             projection: str = "", status: str = "observed",
                             trust: str = "agent_asserted", tool: str = "", query_id: str = "",
                             value_identity_id: int = 0, idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_analysis_evidence(
            snapshot_id, kind, raw or None, projection or None, status, trust, tool, query_id,
            value_identity_id=value_identity_id or None, idempotency_key=idempotency_key))


@mcp.tool(description="Link an EXPLICIT flow transition between two value identities (same "
                      "snapshot). status: hypothesis|supported|demonstrated|rejected|blocked.")
def link_flow_transition(snapshot_id: int, src_vid: int, dst_vid: int, kind: str = "interprocedural",
                         status: str = "hypothesis", trust: str = "agent_asserted",
                         evidence_id: int = 0, caller_symbol: str = "", callee_symbol: str = "",
                         arg_index: int = -1, param_name: str = "", idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().link_flow_transition(
            snapshot_id, src_vid, dst_vid, kind, status, trust, evidence_id or None,
            caller_symbol, callee_symbol, arg_index if arg_index >= 0 else None, param_name,
            idempotency_key))


@mcp.tool(description="Record a hypothesis (statement + optional invariant/scope/next_action).")
def record_hypothesis(statement: str, snapshot_id: int = 0, invariant: str = "", scope: str = "",
                      next_action: str = "", idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_hypothesis(snapshot_id or None, statement, invariant, scope,
                                             next_action, idempotency_key))


@mcp.tool(description="Attach counter-evidence (a 'contradicts' link) to a hypothesis.")
def record_counter_evidence(hypothesis_id: int, evidence_id: int = 0, flow_edge_id: int = 0,
                            rationale: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_counter_evidence(hypothesis_id, evidence_id or None,
                                                   flow_edge_id or None, rationale))


@mcp.tool(description="Record a validation run (test|build|repro|fuzz) with status and optional logs.")
def record_validation_run(snapshot_id: int = 0, kind: str = "test", status: str = "not_run",
                          hypothesis_id: int = 0, logs: str = "", repeat_summary: str = "",
                          idempotency_key: str = "") -> str:
    with _LOCK:
        return _j(_tools().record_validation_run(snapshot_id or None, kind, status,
                                                 hypothesis_id or None, logs or None,
                                                 repeat_summary, idempotency_key))


@mcp.tool(description="Revision-aware recall of evidence. Exact-revision matches first; "
                      "other-revision rows returned in 'historical' labelled stale.")
def query_history(snapshot_id: int = 0, text: str = "", kind: str = "", status: str = "",
                  path: str = "", symbol_id: str = "", limit: int = 20, offset: int = 0) -> str:
    with _LOCK:
        return _j(_tools().query_history(snapshot_id or None, text, kind, status, path, symbol_id,
                                         limit, offset))


@mcp.tool(description="Evaluate chains for a snapshot and report the EXACT missing/weak "
                      "transitions. A chain is 'demonstrated' only if every step is demonstrated.")
def review_chain(snapshot_id: int, goal: str = "") -> str:
    with _LOCK:
        return _j(_tools().review_chain(snapshot_id, goal))


@mcp.tool(description="Append-only reclassification of a sink's type; retracts/stales the chain "
                      "derived from the old classification.")
def reclassify_sink(value_identity_id: int, new_sink_type: str, reason: str = "") -> str:
    with _LOCK:
        return _j(_tools().reclassify_sink(value_identity_id, new_sink_type, reason))


@mcp.tool(description="Export a structured evidence bundle for a snapshot (snapshot identity, "
                      "chains, bounded evidence previews, findings).")
def export_evidence_bundle(snapshot_id: int, limit: int = 100) -> str:
    with _LOCK:
        return _j(_tools().export_evidence_bundle(snapshot_id, limit))


def main() -> None:
    print(f"[agentmem-firefox-research] db={os.environ.get('AGENTMEM_DB', 'research.db')}",
          file=sys.stderr, flush=True)
    mcp.run()


if __name__ == "__main__":
    main()
