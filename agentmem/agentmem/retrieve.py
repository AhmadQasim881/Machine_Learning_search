"""
agentmem.retrieve — hybrid retrieval with composite reranking (spec §3.2).

Two retrievers (exact SQL + graph BFS) carry the core; an optional semantic
retriever plugs in when an embedding provider is configured. Results are fused
and reranked by the Generative-Agents composite score (relevance + importance +
recency-in-STEPS + confidence), with pinned nodes floored so verified assets are
never buried. Retrieval bumps `last_access_step` (reconsolidation).
"""
from __future__ import annotations

import json
import math
from typing import Optional

from . import config
from . import embeddings as emb
from .store import Store


def semantic(store: Store, query_vec: list, top_k: int = 50,
             type: Optional[str] = None) -> list[int]:
    """Cosine top-k over stored node embeddings (brute force; fine for modest N).
    Returns node ids ranked by similarity."""
    scored = []
    for r in store.nodes_with_embeddings(type=type):
        try:
            v = emb.from_blob(r["embedding"])
        except Exception:        # noqa: BLE001 — a malformed blob just skips
            continue
        scored.append((r["id"], emb.cosine(query_vec, v)))
    scored.sort(key=lambda t: t[1], reverse=True)
    return [nid for nid, _ in scored[:top_k]]


def _rrf(ranked_lists: list[list[int]], k: int = config.RRF_K) -> dict[int, float]:
    """Reciprocal-rank fusion of several ranked id lists."""
    out: dict[int, float] = {}
    for lst in ranked_lists:
        for rank, nid in enumerate(lst):
            out[nid] = out.get(nid, 0.0) + 1.0 / (k + rank + 1)
    return out


def _recency(store: Store, node) -> float:
    last = node["last_access_step"] if node["last_access_step"] is not None else node["created_step"] or 0
    return math.exp(-config.RECENCY_LAMBDA * max(0, store.step - last))


def composite_score(store: Store, node, relevance: float = 0.0) -> float:
    s = (config.W_RELEVANCE * relevance
         + config.W_IMPORTANCE * (node["importance"] / 10.0)
         + config.W_RECENCY * _recency(store, node)
         + config.W_CONFIDENCE * (node["confidence"] or 0.0))
    if node["pinned"]:
        s = max(s, config.PIN_FLOOR)
    return round(s, 4)


def exact(store: Store, type: Optional[str] = None, host: Optional[str] = None,
          vuln_class: Optional[str] = None) -> list:
    """Exact structured lookup by type/host/vuln_class (answers 'all params on
    host X', 'all confirmed findings', ...)."""
    q = "SELECT * FROM nodes WHERE status!='invalidated'"
    args: list = []
    if type:
        q += " AND type=?"; args.append(type)
    rows = store.conn.execute(q, args).fetchall()
    out = []
    for r in rows:
        a = json.loads(r["attrs_json"])
        if host and a.get("host") != host:
            continue
        if vuln_class and a.get("vuln_class") != vuln_class:
            continue
        out.append(r)
    return out


def graph_neighbors(store: Store, node_id: int, hops: int = 2,
                    rel_types: Optional[set] = None) -> list[int]:
    """BFS from a node over typed edges — the read-time 'pull everything
    reachable from what I just found' primitive (half of chain discovery)."""
    seen = {node_id}
    frontier = [node_id]
    order: list[int] = []
    for _ in range(hops):
        nxt = []
        for nid in frontier:
            for e in store.edges_from(nid):
                if rel_types and e["rel_type"] not in rel_types:
                    continue
                if e["dst_id"] not in seen:
                    seen.add(e["dst_id"]); nxt.append(e["dst_id"]); order.append(e["dst_id"])
        frontier = nxt
        if not frontier:
            break
    return order


def recall(store: Store, type: Optional[str] = None, host: Optional[str] = None,
           vuln_class: Optional[str] = None, limit: int = 20,
           seed_node: Optional[int] = None, query: Optional[str] = None,
           provider=None) -> list[dict]:
    """Hybrid recall: exact candidates (+ graph neighbors of a seed + optional
    semantic matches for a free-text `query` when an embedding `provider` is set),
    fused by RRF and reranked by the composite score. Returns
    [{node_id, type, score, attrs}]."""
    exact_ids = [r["id"] for r in exact(store, type=type, host=host, vuln_class=vuln_class)]
    cand = {nid: store.get_node(nid) for nid in exact_ids}

    graph_ids: list[int] = []
    if seed_node is not None:
        for nid in graph_neighbors(store, seed_node):
            r = store.get_node(nid)
            if r and r["status"] != "invalidated":
                cand.setdefault(nid, r)
                graph_ids.append(nid)

    sem_ids: list[int] = []
    if query and provider is not None:
        qv = provider.encode(query)
        if qv is not None:
            sem_ids = semantic(store, qv, top_k=limit * 3, type=type)
            for nid in sem_ids:
                r = store.get_node(nid)
                if r and r["status"] != "invalidated":
                    cand.setdefault(nid, r)

    # free-text WITHOUT embeddings: a query must never be silently ignored. Fall
    # back to a bounded SQL substring match over the node key + attributes so recall
    # still responds to the query text (documented degraded mode vs. semantic).
    text_ids: list[int] = []
    if query and provider is None:
        like = f"%{query.lower()}%"
        tq = "SELECT id FROM nodes WHERE status!='invalidated' AND (lower(canonical_key) LIKE ? OR lower(attrs_json) LIKE ?)"
        targs: list = [like, like]
        if type:
            tq += " AND type=?"; targs.append(type)
        tq += " LIMIT ?"; targs.append(limit * 5)
        for r in store.conn.execute(tq, targs).fetchall():
            nid = r["id"]
            if nid not in cand:
                n = store.get_node(nid)
                if n:
                    cand[nid] = n
            text_ids.append(nid)

    # RRF across the retrievers blends with the composite score
    rrf = _rrf([exact_ids, graph_ids, sem_ids, text_ids]) if (sem_ids or text_ids) else {}

    scored = []
    for r in cand.values():
        scored.append({"node_id": r["id"], "type": r["type"],
                       "score": composite_score(store, r) + rrf.get(r["id"], 0.0),
                       "status": r["status"], "pinned": bool(r["pinned"]),
                       "attrs": json.loads(r["attrs_json"])})
    scored.sort(key=lambda d: d["score"], reverse=True)
    top = scored[:limit]
    # reconsolidation: bump only the results we actually return, in one statement
    ids = [d["node_id"] for d in top]
    if ids:
        store.conn.execute(
            f"UPDATE nodes SET last_access_step=?, strength=strength+1 "
            f"WHERE id IN ({','.join('?' * len(ids))})", (store.step, *ids))
        store._commit()
    return top
