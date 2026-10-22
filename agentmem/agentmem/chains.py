"""
agentmem.chains — multi-step exploit-chain detection (spec §4.3).

The deterministic chain engine. It builds `ENABLES` edges between findings by
capability unification (A ENABLES B iff A.provides satisfies some B.requires),
then does a bounded best-first search accumulating provided capabilities along
each path. When a path's accumulated capabilities satisfy an escalation rule, a
`Chain` to that high-value goal is materialized, with every step cited back to
its evidence.

This runs with ZERO LLM and ZERO embeddings — chains are found by graph search
over typed capability tokens, not by similarity. An LLM (optional) only narrates
a chain the matcher already proved.
"""
from __future__ import annotations

from typing import Optional

from . import capabilities as caps
from . import config
from .store import Store

# node types that can carry capabilities and participate in chains
_CHAIN_TYPES = ("finding", "credential", "technique")


def _base_available(store: Store) -> list:
    """Capabilities available for free: confirmed credentials + a 'reachable'
    primitive + provides of findings that need nothing (entry points)."""
    avail: list = [("reachable", {})]
    for r in store.pinned_nodes():
        if r["type"] == "credential" and r["status"] != "invalidated":
            avail.extend(store.get_provides(r["id"]))
    return avail


def _chain_nodes(store: Store) -> list:
    rows = []
    for t in _CHAIN_TYPES:
        rows.extend(store.nodes_by_type(t))
    return rows


def rebuild_enables(store: Store) -> int:
    """(Re)compute ENABLES edges across all capability-bearing nodes via the
    provides/requires token index. Returns the number of edges asserted."""
    nodes = _chain_nodes(store)
    provides = {n["id"]: store.get_provides(n["id"]) for n in nodes}
    requires = {n["id"]: store.get_requires(n["id"]) for n in nodes}
    n_edges = 0
    for a in nodes:
        aid = a["id"]
        if not provides[aid]:
            continue
        # candidate targets: nodes that require a token we provide
        cand: set[int] = set()
        for name, _ in provides[aid]:
            cand.update(store.nodes_with_requires_token(name))
        for bid in cand:
            if bid == aid:
                continue
            # does any provided token satisfy any required token?
            binding = None
            for req in requires.get(bid, []):
                binding = caps.any_unifies(provides[aid], req)
                if binding is not None:
                    break
            if binding is not None:
                conf = min(a["confidence"], store.get_node(bid)["confidence"]) or 0.5
                store.add_edge(aid, bid, "ENABLES", attrs=binding,
                               confidence=conf, trust="agent_asserted",
                               provenance=[aid, bid])
                n_edges += 1
    return n_edges


def detect(store: Store) -> list[int]:
    """Full detection pass: rebuild ENABLES, search for goal-reaching paths,
    materialize Chain nodes. Returns the chain row ids found/updated."""
    rebuild_enables(store)
    nodes = {n["id"]: n for n in _chain_nodes(store)}
    provides = {nid: store.get_provides(nid) for nid in nodes}
    requires = {nid: store.get_requires(nid) for nid in nodes}
    base = _base_available(store)

    # adjacency over current ENABLES edges
    adj: dict[int, list[tuple[int, int]]] = {nid: [] for nid in nodes}
    for e in store.all_edges("ENABLES"):
        if e["src_id"] in adj and e["dst_id"] in nodes:
            adj[e["src_id"]].append((e["dst_id"], e["id"]))

    def requires_satisfied(nid: int, avail: list) -> bool:
        return all(caps.any_unifies(avail, req) is not None for req in requires.get(nid, []))

    # entry points: nodes whose requires are satisfied by base alone
    entries = [nid for nid in nodes if requires_satisfied(nid, base)]

    found: list[int] = []
    seen_chains: set[str] = set()

    # best-first DFS with caps; a "path" accumulates provided capabilities
    def walk(path: list[int], edges: list[Optional[int]], avail: list, conf: float):
        if len(path) > config.CHAIN_MAX_DEPTH:
            return
        # check goals reached by the capabilities accumulated so far
        for goal, severity in caps.reached_goals(avail):
            cid = _materialize(store, path, edges, goal, severity, conf, nodes, seen_chains)
            if cid is not None:
                found.append(cid)
        # expand
        tail = path[-1]
        for (nxt, eid) in adj.get(tail, [])[: config.CHAIN_MAX_WIDTH]:
            if nxt in path:
                continue
            new_avail = avail + provides.get(nxt, [])
            if not requires_satisfied(nxt, new_avail):
                continue
            nconf = conf * (nodes[nxt]["confidence"] or 0.5)
            if nconf < config.CHAIN_MIN_CONFIDENCE:
                continue
            walk(path + [nxt], edges + [eid], new_avail, nconf)

    for nid in entries:
        avail0 = base + provides.get(nid, [])
        walk([nid], [None], avail0, nodes[nid]["confidence"] or 0.5)
    return found


def _materialize(store: Store, path: list[int], edges: list, goal: str,
                 severity: int, conf: float, nodes: dict, seen: set) -> Optional[int]:
    dedup = f"{goal}|" + ",".join(str(x) for x in sorted(path))
    if dedup in seen:
        return None
    seen.add(dedup)
    all_confirmed = all(nodes[nid]["status"] == "confirmed" for nid in path)
    status = "confirmed" if all_confirmed else "candidate"
    score = round(conf * (severity / 10.0), 4)
    narrative = _narrate(store, path, goal, nodes)
    steps = list(zip(path, edges))
    return store.upsert_chain(goal, score, severity, status, narrative, steps, dedup)


def _narrate(store: Store, path: list[int], goal: str, nodes: dict) -> str:
    parts = []
    for nid in path:
        a = store.node_attrs(nid)
        label = a.get("vuln_class") or a.get("name") or nodes[nid]["type"]
        loc = a.get("host", "")
        if a.get("path"):
            loc = f"{loc}{a['path']}"
        parts.append(f"{label}" + (f" @ {loc}" if loc else ""))
    return " -> ".join(parts) + f"  ==>  {goal.upper()}"


# --- backward chaining: what probe would complete a chain? ----------------- #
def next_probes(store: Store) -> list[dict]:
    """Goal-directed suggestions: for each escalation rule not yet fully reached,
    report the missing capability token(s) — the agent's next-best probe."""
    nodes = _chain_nodes(store)
    avail = list(_base_available(store))
    for n in nodes:
        avail.extend(store.get_provides(n["id"]))
    out = []
    for rule in config.ESCALATION_RULES:
        missing = [need for need in rule["need"] if caps.any_unifies(avail, need) is None]
        if missing and len(missing) < len(rule["need"]):
            # partially satisfied — one more capability would complete it
            for name, attrs in missing:
                out.append({
                    "goal": rule["goal"],
                    "severity": config.GOAL_SEVERITY.get(rule["goal"], 5),
                    "missing_capability": name,
                    "constraints": attrs,
                    "suggestion": f"obtain capability '{name}' to escalate toward {rule['goal']}",
                })
    # rank by goal severity
    out.sort(key=lambda d: d["severity"], reverse=True)
    return out
