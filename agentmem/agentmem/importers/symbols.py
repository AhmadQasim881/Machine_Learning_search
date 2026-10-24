"""
agentmem.importers.symbols — import a normalized symbol / cross-reference index
(from a Searchfox-derived adapter or a Clang / compile_commands.json indexer) into
the research store as `code_symbols` + `symbol_relations`.

The memory layer does not parse raw Searchfox data or run Clang — that is the
indexer's job. It ingests the indexer's NORMALIZED output:

    {
      "tool": "searchfox", "version": "2024-...",
      "symbols": [
        {"symbol_id": "cpp:mozilla::Foo::Parse", "qualified_name": "mozilla::Foo::Parse",
         "language": "cpp", "kind": "method", "path": "dom/Foo.cpp",
         "start_line": 120, "end_line": 180, "trust_domain": "content-process"},
        ...
      ],
      "relations": [
        {"src": "cpp:mozilla::Foo::Parse", "dst": "cpp:mozilla::Bar::Write",
         "relation": "calls", "dispatch": "virtual",
         "callsite_path": "dom/Foo.cpp", "callsite_line": 140, "confidence": 0.9},
        ...
      ]
    }

Every record is snapshot-scoped and carries tool provenance. Call edges keep their
dispatch kind, so a possible (virtual / function-pointer) target is never
presented as an observed runtime execution.
"""
from __future__ import annotations

from typing import Optional


def import_symbols(mem, snapshot_id: int, index, tool: str = "", trust: str = "tool_verified") -> dict:
    """Import a normalized symbol index (dict, or JSON string) into `snapshot_id`.
    Returns a summary of what was created."""
    import json
    if isinstance(index, (bytes, bytearray)):
        index = index.decode("utf-8", "replace")
    if isinstance(index, str):
        index = json.loads(index)
    if not isinstance(index, dict) or not ("symbols" in index or "relations" in index):
        raise ValueError("not a symbol index (expected 'symbols' and/or 'relations')")

    mem._require_snapshot(snapshot_id)
    tool_name = tool or index.get("tool") or "symbol-index"
    tool_version = index.get("version") or ""
    prov = mem.add_provenance(snapshot_id, tool=tool_name, tool_version=tool_version,
                              actor=tool_name, actor_kind="tool", trust=trust)

    summary = {"snapshot_id": snapshot_id, "symbols": 0, "relations": 0,
               "unknown_relation_endpoints": 0}
    known: set = set()
    for s in index.get("symbols") or []:
        sid = s.get("symbol_id") or s.get("qualified_name")
        if not sid:
            continue
        mem.register_symbol(snapshot_id, sid, qualified_name=s.get("qualified_name", ""),
                            language=s.get("language", ""), kind=s.get("kind", "function"),
                            path=s.get("path", ""), start_line=s.get("start_line", 0),
                            end_line=s.get("end_line", 0), trust_domain=s.get("trust_domain", ""),
                            provenance_id=prov)
        known.add(sid)
        summary["symbols"] += 1

    for r in index.get("relations") or []:
        src, dst = r.get("src"), r.get("dst")
        if not src or not dst:
            continue
        rel = r.get("relation", "calls")
        boundary_id = r.get("boundary_id")
        mem.link_symbols(snapshot_id, src, dst, relation=rel,
                         dispatch=r.get("dispatch", "direct"),
                         callsite_path=r.get("callsite_path", ""),
                         callsite_line=r.get("callsite_line", 0),
                         boundary_id=boundary_id, confidence=r.get("confidence", 0.5),
                         provenance_id=prov)
        summary["relations"] += 1
        if known and (src not in known or dst not in known):
            # a relation may reference a symbol outside the imported set (e.g. a
            # cross-TU or external target) — recorded, but flagged so coverage gaps
            # stay visible rather than looking resolved.
            summary["unknown_relation_endpoints"] += 1
    return summary
