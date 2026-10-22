"""
agentmem.forget — decay as a RANKING signal only, with pinning (spec §3.4).

Requirement: never forget. So nothing is ever hard-deleted. Ebbinghaus strength
(MemoryBank) `R = exp(-delta_step / S)` only DOWN-RANKS retrieval priority; recall
strengthens S. Verified assets are PINNED (score floored, never decayed). Stale or
contradicted facts are SOFT-invalidated (status='invalidated'), preserving the
audit trail and the ability to reconstruct chains built on earlier state.
"""
from __future__ import annotations

import math

from .store import Store

# nodes of these types are auto-pinned the moment they are confirmed
_AUTO_PIN_TYPES = {"credential"}


def retention(store: Store, node) -> float:
    """Ebbinghaus retention R in (0,1]; 1.0 for pinned nodes."""
    if node["pinned"]:
        return 1.0
    s = node["strength"] or store_default_strength()
    delta = max(0, store.step - (node["last_access_step"] or node["created_step"] or 0))
    return math.exp(-delta / max(1.0, s))


def store_default_strength() -> float:
    from . import config
    return config.DECAY_S0


def auto_pin(store: Store) -> int:
    """Pin anything that must never be forgotten: credentials, confirmed findings,
    confirmed chains, and any node participating in a chain. Returns count pinned."""
    n = 0
    # confirmed findings + auto-pin types
    for r in store.conn.execute(
            "SELECT id,type,status,pinned FROM nodes WHERE pinned=0").fetchall():
        if r["type"] in _AUTO_PIN_TYPES or (r["type"] == "finding" and r["status"] == "confirmed"):
            store.pin(r["id"]); n += 1
    # nodes participating in any LIVE chain (not one that was retracted)
    for r in store.conn.execute(
            "SELECT DISTINCT cs.node_id FROM chain_steps cs "
            "JOIN nodes nd ON nd.id=cs.node_id "
            "JOIN chains ch ON ch.id=cs.chain_id "
            "WHERE nd.pinned=0 AND ch.status!='invalidated'").fetchall():
        store.pin(r["node_id"]); n += 1
    return n


def soft_invalidate(store: Store, node_id: int, reason: str = "") -> None:
    """Mark a fact no longer valid WITHOUT deleting it (audit + chain history)."""
    store.update_node(node_id, status="invalidated")
    if reason:
        store.add_lesson(node_id, "invalidation", reason)
    # close its open edges bi-temporally
    store.conn.execute(
        "UPDATE edges SET valid_to=? WHERE (src_id=? OR dst_id=?) AND valid_to IS NULL",
        (store.step, node_id, node_id))
    store._commit()
    # retract any chain that depended on this node (never surface a withdrawn chain)
    from . import chains as _chains
    _chains.retract_invalidated(store)
    store.mark_dirty()
