"""
agentmem.importers.sarif — import CodeQL / SARIF 2.1.0 results into the research
store as scoped value identities + EXPLICIT flow edges + evidence.

This is the adapter that makes the memory useful at scale: instead of a human
hand-entering every taint fact, a CodeQL run's `codeFlows` become the flow graph.
It honors the core rule — identities come from EXACT SARIF locations (uri +
region + logical symbol), and edges come from CodeQL's own threadFlow ordering, so
nothing is inferred from a shared variable name.

Honest modeling of certainty:
  * A CodeQL path is tool-derived EVIDENCE, not a runtime demonstration — flow
    edges are imported with status 'supported' and trust 'tool_verified'
    (never 'demonstrated'; that needs dynamic validation).
  * The raw SARIF is preserved verbatim as one immutable artifact; each result's
    evidence row references it and carries a bounded message projection.

Usage:
    from agentmem import ResearchMemory
    from agentmem.importers import import_sarif
    m = ResearchMemory("firefox.db")
    snap = m.register_snapshot("firefox", "<commit>", scope="dom")
    summary = import_sarif(m, snap, open("results.sarif").read())
"""
from __future__ import annotations

import json
from typing import Optional

# ruleId keyword -> our sink_type vocabulary (see profiles._SINK_GOAL)
_RULE_SINK_HINTS = [
    ("sql", "sql"), ("nosql", "nosql"), ("command", "command"), ("shell", "command"),
    ("argument-injection", "command"), ("code-injection", "eval"), ("eval", "eval"),
    ("deserial", "deserialize"), ("unsafe-deserialization", "deserialize"),
    ("xxe", "xxe"), ("xml-external", "xxe"), ("path-injection", "path"),
    ("tainted-path", "path"), ("zipslip", "path"), ("file", "file_write"),
    ("ssrf", "ssrf"), ("request-forgery", "ssrf"), ("open-redirect", "open_redirect"),
    ("redirect", "open_redirect"), ("xss", "xss"), ("reflected", "xss"),
    ("ldap", "ldap"), ("log-injection", "log"), ("header", "header"),
    ("format-string", "format_string"), ("tainted-format", "format_string"),
    ("overflow", "buffer"), ("buffer", "buffer"), ("out-of-bounds", "buffer"),
    ("tainted-arithmetic", "integer_overflow"), ("integer", "integer_overflow"),
    ("size", "buffer"), ("alloc", "buffer"), ("comparison", "generic"),
]


def _sink_type_for(rule_id: str) -> str:
    r = (rule_id or "").lower()
    for needle, sink in _RULE_SINK_HINTS:
        if needle in r:
            return sink
    return "generic"


def _loc_fields(physical: dict) -> tuple:
    """Return (uri, start_line, start_col, end_line, end_col) from a SARIF
    physicalLocation (missing pieces default to 0/'')."""
    uri = ((physical or {}).get("artifactLocation") or {}).get("uri", "")
    region = (physical or {}).get("region") or {}
    return (uri, region.get("startLine", 0), region.get("startColumn", 0),
            region.get("endLine", region.get("startLine", 0)), region.get("endColumn", 0))


def _logical_symbol(location: dict) -> str:
    for ll in location.get("logicalLocations") or []:
        name = ll.get("fullyQualifiedName") or ll.get("name")
        if name:
            return name
    return ""


def _value_name(tf_location: dict, start_line: int) -> str:
    msg = ((tf_location.get("location") or {}).get("message") or {}).get("text")
    return msg or f"expr@{start_line}"


def import_sarif(mem, snapshot_id: int, sarif, trust: str = "tool_verified",
                 status: str = "supported", default_tool: str = "CodeQL") -> dict:
    """Import a SARIF document into `snapshot_id`. `sarif` is a JSON string or an
    already-parsed dict. Returns a summary of what was created."""
    if isinstance(sarif, (bytes, bytearray)):
        sarif = sarif.decode("utf-8", "replace")
    raw_text = sarif if isinstance(sarif, str) else json.dumps(sarif)
    doc = json.loads(sarif) if isinstance(sarif, str) else sarif
    if not isinstance(doc, dict) or "runs" not in doc:
        raise ValueError("not a SARIF document (missing 'runs')")

    mem._require_snapshot(snapshot_id)
    # preserve the raw SARIF verbatim as one immutable artifact (deduped)
    sarif_artifact = mem.store.put_artifact(raw_text, media_type="application/sarif+json",
                                            producing_run="codeql-sarif")
    summary = {"snapshot_id": snapshot_id, "runs": 0, "results": 0, "flows": 0,
               "value_identities": 0, "flow_edges": 0, "evidence": 0,
               "sarif_artifact": sarif_artifact["sha256"]}

    for run in doc.get("runs") or []:
        summary["runs"] += 1
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = driver.get("name") or default_tool
        tool_version = driver.get("version") or driver.get("semanticVersion") or ""

        for result in run.get("results") or []:
            summary["results"] += 1
            rule_id = result.get("ruleId") or ((result.get("rule") or {}).get("id")) or ""
            sink_type = _sink_type_for(rule_id)
            message = ((result.get("message") or {}).get("text")) or rule_id

            prov = mem.add_provenance(snapshot_id, tool=tool_name, tool_version=tool_version,
                                      query_id=rule_id, actor=tool_name, actor_kind="tool",
                                      trust=trust, raw_artifact_id=sarif_artifact["id"])
            # one evidence row per result, referencing the raw SARIF artifact
            ev = mem.add_evidence(snapshot_id, "static_analysis", projection=f"[{rule_id}] {message}",
                                  status=status, trust=trust, provenance_id=prov)
            # link the raw artifact to this evidence row (projection already bounded)
            mem.conn.execute("UPDATE evidence SET artifact_id=? WHERE id=?",
                             (sarif_artifact["id"], ev))
            summary["evidence"] += 1

            code_flows = result.get("codeFlows") or []
            if not code_flows:
                # no path: record the result's own location as a sink identity
                locs = result.get("locations") or []
                if locs:
                    uri, sl, sc, el, ec = _loc_fields((locs[0].get("physicalLocation")) or {})
                    sym = _logical_symbol(locs[0])
                    mem.add_value_identity(snapshot_id, uri, _value_name(locs[0], sl), role="sink",
                                           symbol_id=sym, start_line=sl, end_line=el,
                                           sink_type=sink_type, tool=tool_name, run_id=rule_id,
                                           provenance_id=prov)
                    summary["value_identities"] += 1
                continue

            for cf in code_flows:
                for tf in cf.get("threadFlows") or []:
                    tlocs = tf.get("locations") or []
                    if len(tlocs) < 1:
                        continue
                    summary["flows"] += 1
                    vids, metas = [], []
                    n = len(tlocs)
                    for i, tl in enumerate(tlocs):
                        phys = (tl.get("location") or {}).get("physicalLocation") or {}
                        uri, sl, sc, el, ec = _loc_fields(phys)
                        sym = _logical_symbol(tl.get("location") or {})
                        role = "source" if i == 0 else ("sink" if i == n - 1 else "transform")
                        vid = mem.add_value_identity(
                            snapshot_id, uri, _value_name(tl, sl), role=role, symbol_id=sym,
                            start_line=sl, end_line=el,
                            sink_type=sink_type if role == "sink" else "",
                            tool=tool_name, run_id=rule_id, provenance_id=prov)
                        vids.append(vid)
                        metas.append((uri, sym))
                        summary["value_identities"] += 1
                    for i in range(len(vids) - 1):
                        same_fn = metas[i][1] and metas[i][1] == metas[i + 1][1] and metas[i][0] == metas[i + 1][0]
                        mem.add_flow_edge(
                            snapshot_id, vids[i], vids[i + 1],
                            kind="intraprocedural" if same_fn else "interprocedural",
                            status=status, trust=trust, provenance_id=prov, evidence_id=ev,
                            caller_symbol=metas[i][1], callee_symbol=metas[i + 1][1])
                        summary["flow_edges"] += 1
    return summary
