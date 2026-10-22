"""
agentmem.memory — the Memory facade: the ONLY API the agent needs.

Wires together the store, secrets vault, write pipeline, retrieval, chain engine,
forgetting, and the persisted working set. A bug-bounty agent calls:

    m = Memory("campaign.db")
    m.observe(request, response)                       # log raw traffic (lossless)
    m.add_finding("open_redirect", host=..., param=..., confirmed=True, oracle="302")
    m.add_credential("session", subject="userB", value="...")
    chains = m.chains()                                # discovered exploit chains
    probes = m.next_probes()                           # what to try next to complete one
    hits   = m.recall(type="finding", host=...)        # ranked recall
    m.reflect(); m.close()                             # pin verified assets, persist

Everything persists to SQLite and reloads with rehydrate() after a restart.
"""
from __future__ import annotations

from typing import Optional

from . import chains as chainmod
from . import forget
import os

from . import embeddings as emb
from . import profiles
from . import reflect as reflectmod
from . import retrieve
from . import write
from .security import SecretsVault
from .store import Store
from .working import WorkingMemory


class Memory:
    def __init__(self, path: str = "campaign.db", profile=None, embeddings: bool = False):
        """`profile` selects the domain ontology (default: web bug-bounty). Pass
        `agentmem.profiles.CODEREVIEW` (or a custom Profile) to retarget the same
        engine to another domain. `embeddings=True` enables the dependency-free
        semantic retriever + SAME_AS synonym edges (or pass an EmbeddingProvider)."""
        self.store = Store(path)
        self.vault = SecretsVault(self.store)
        self.working = WorkingMemory(self.store, vault=self.vault)
        self.profile = profile or profiles.WEB
        if embeddings is True:
            self.embed = emb.HashingProvider()
        elif embeddings and embeddings is not False:
            self.embed = embeddings          # a custom EmbeddingProvider
        else:
            self.embed = None

    def _embed(self, node_id: int) -> None:
        if self.embed is None:
            return
        node = self.store.get_node(node_id)
        if not node:
            return
        import json as _json
        vec = self.embed.encode(emb.text_for(_json.loads(node["attrs_json"]), node["type"]))
        if vec is not None:
            self.store.set_embedding(node_id, emb.to_blob(vec))

    # ---- lifecycle ------------------------------------------------------- #
    def tick(self) -> int:
        """Advance the campaign clock (one agent step)."""
        return self.store.tick()

    def rehydrate(self) -> dict:
        """Rebuild the working set after a restart."""
        return self.working.rehydrate()

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Memory":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- write ----------------------------------------------------------- #
    def observe(self, request: str, response: str = "",
                trust: str = "target_derived", source: str = "http") -> int:
        return write.observe(self.store, request, response, trust, source)

    def set_target(self, program: str, in_scope: list, out_scope: Optional[list] = None) -> int:
        from . import canonical as C
        return self.store.upsert_node(
            "target", C._key("target", program),
            {"program": program, "in_scope": in_scope, "out_scope": out_scope or []},
            importance=9, confidence=1.0, trust="agent_asserted", status="confirmed")

    def add_finding(self, vuln_class: str, host: str = "", path: str = "/",
                    param: str = "", confirmed: bool = False, oracle: str = "",
                    attrs: Optional[dict] = None, trust: str = "agent_asserted",
                    severity: int = 5, obs_id: Optional[int] = None) -> int:
        nid = write.add_finding(self.store, vuln_class, host, path, param,
                                confirmed, oracle, attrs, trust, obs_id=obs_id,
                                severity=severity, profile=self.profile)
        self._embed(nid)
        return nid

    def add_fact(self, kind: str, canonical_key: str, attrs: Optional[dict] = None,
                 node_type: str = "finding", confirmed: bool = False, oracle: str = "",
                 trust: str = "agent_asserted", severity: int = 5,
                 obs_id: Optional[int] = None) -> int:
        """Domain-agnostic ingest (any profile). `kind` selects the capability
        extractor; `canonical_key` is the dedup identity (build it with the
        profile's key helper). Pass `obs_id` (from observe()) for provenance +
        consensus promotion."""
        nid = write.add_fact(self.store, kind, canonical_key, attrs, self.profile,
                             node_type, confirmed, oracle, trust, severity, obs_id)
        self._embed(nid)
        return nid

    # ---- code-review (taint) sugar — only meaningful under CODEREVIEW -------- #
    def add_taint_source(self, file: str, var: str, symbol: str = "", line: int = 0,
                         confirmed: bool = True, oracle: str = "source") -> int:
        key = profiles.cr_key("taint_source", file, symbol, var, line)
        return self.add_fact("taint_source", key,
                             {"file": file, "var": var, "symbol": symbol, "line": line},
                             confirmed=confirmed, oracle=oracle)

    def add_taint_prop(self, file: str, var_in: str, var_out: str, symbol: str = "",
                       line: int = 0, confirmed: bool = True, oracle: str = "dataflow") -> int:
        key = profiles.cr_key("taint_prop", file, symbol, var_out, line)
        return self.add_fact("taint_prop", key,
                             {"file": file, "var_in": var_in, "var_out": var_out,
                              "symbol": symbol, "line": line},
                             confirmed=confirmed, oracle=oracle)

    def add_taint_sink(self, file: str, var: str, sink_type: str, symbol: str = "",
                       line: int = 0, confirmed: bool = True, oracle: str = "sink",
                       severity: int = 8) -> int:
        key = profiles.cr_key("taint_sink", file, symbol, var, line)
        return self.add_fact("taint_sink", key,
                             {"file": file, "var": var, "sink_type": sink_type,
                              "symbol": symbol, "line": line},
                             confirmed=confirmed, oracle=oracle, severity=severity)

    def add_technique_rule(self, name: str, provides: list, requires: list,
                           confirmed: bool = True, attrs: Optional[dict] = None) -> int:
        return write.add_technique_rule(self.store, name, provides, requires, confirmed, attrs)

    def add_credential(self, kind: str, subject: str, value: str = "",
                       provides_tokens: Optional[list] = None) -> tuple[int, str]:
        return write.add_credential(self.store, self.vault, kind, subject, value, provides_tokens)

    def note_payload(self, host: str, path: str, param: str, template: str,
                     value: str, outcome: str, success: bool, method: str = "GET") -> int:
        return write.note_payload(self.store, host, path, param, template, value,
                                  outcome, success, method)

    def already_tried(self, host: str, path: str, param: str, template: str,
                      method: str = "GET") -> bool:
        return write.already_tried(self.store, host, path, param, template, method)

    # ---- read ------------------------------------------------------------ #
    def recall(self, type: Optional[str] = None, host: Optional[str] = None,
               vuln_class: Optional[str] = None, limit: int = 20,
               seed_node: Optional[int] = None, query: Optional[str] = None) -> list[dict]:
        """Hybrid recall. Pass a free-text `query` for semantic matching when the
        memory was created with embeddings=True."""
        return retrieve.recall(self.store, type=type, host=host, vuln_class=vuln_class,
                               limit=limit, seed_node=seed_node, query=query,
                               provider=self.embed)

    def chains(self, include_invalidated: bool = False) -> list[dict]:
        """Discovered exploit chains, highest severity first, with cited steps.
        Detection runs lazily (only when new facts were written since last call).
        Retracted (invalidated) chains are hidden by default."""
        if self.store.take_dirty():
            chainmod.detect(self.store, self.profile)
        out = []
        for c in self.store.chains():
            if c["status"] == "invalidated" and not include_invalidated:
                continue
            steps = []
            for cs in self.store.chain_steps(c["id"]):
                a = self.store.node_attrs(cs["node_id"])
                steps.append({"node_id": cs["node_id"],
                              "label": a.get("vuln_class") or a.get("name") or "node",
                              "host": a.get("host", ""), "path": a.get("path", "")})
            out.append({"id": c["id"], "goal": c["goal"], "severity": c["severity"],
                        "score": c["score"], "status": c["status"],
                        "narrative": c["narrative"], "steps": steps})
        return out

    def next_probes(self) -> list[dict]:
        """Goal-directed: the missing capabilities that would complete a chain."""
        return chainmod.next_probes(self.store, self.profile)

    # ---- maintenance ----------------------------------------------------- #
    def pin(self, node_id: int) -> None:
        self.store.pin(node_id)

    def invalidate(self, node_id: int, reason: str = "") -> None:
        forget.soft_invalidate(self.store, node_id, reason)

    def reflect(self) -> dict:
        """Consolidation pass: full chain re-detect, pin verified assets
        (never-forget), persist the next-probe queue as hypothesis nodes, and
        rebuild per-host portrait summaries. All deterministic (no LLM)."""
        self.store.take_dirty()          # we are about to run a full detect
        chainmod.detect(self.store, self.profile)
        pinned = forget.auto_pin(self.store)
        hyps = reflectmod.materialize_hypotheses(self.store, self.profile)
        portraits = reflectmod.build_portraits(self.store, self.profile)
        synonyms = reflectmod.link_synonyms(self.store) if self.embed else 0
        return {"pinned": pinned, "chains": len(self.store.chains()),
                "hypotheses": hyps, "portraits": portraits, "synonyms": synonyms}

    def get_secret(self, handle: str):
        """Resolve a credential value from the vault by handle (use sparingly)."""
        return self.vault.get(handle)

    def redact(self, text: str) -> str:
        """Replace any stored secret value in `text` with its handle."""
        return self.vault.redact(text)

    def stats(self) -> dict:
        """Cheap read-only health snapshot (no detection, no mutation)."""
        s = self.store
        by_type = {r["type"]: r["n"] for r in s.conn.execute(
            "SELECT type, COUNT(*) n FROM nodes GROUP BY type").fetchall()}
        invalid = s.conn.execute(
            "SELECT COUNT(*) n FROM nodes WHERE status='invalidated'").fetchone()["n"]
        live_chains = s.conn.execute(
            "SELECT COUNT(*) n FROM chains WHERE status!='invalidated'").fetchone()["n"]
        db_bytes = os.path.getsize(s.path) if os.path.exists(s.path) else 0
        return {"step": s.step, "nodes_by_type": by_type, "invalidated": invalid,
                "observations": s.conn.execute("SELECT COUNT(*) n FROM observations").fetchone()["n"],
                "live_chains": live_chains, "db_bytes": db_bytes}

    def context(self, budget_chars: int = 4000) -> str:
        """Render a compact, SECRET-REDACTED memory block to inject into an LLM
        prompt — the most common integration path. Prioritizes pinned/high-severity
        items and truncates to `budget_chars`. This is the one call an agent needs
        to put 'what memory knows' in front of the model safely."""
        ws = self.working.rehydrate()
        lines = [f"# MEMORY (campaign step {ws['step']})"]
        if ws.get("targets"):
            t = ws["targets"][0]
            lines.append(f"Target: {t.get('program', '?')}  in-scope={t.get('in_scope', [])}")
        ch = self.chains()
        if ch:
            lines.append("\n## Confirmed/candidate exploit chains (highest severity first)")
            for c in ch:
                lines.append(f"- [sev {c['severity']} {c['status']}] {c['goal']}: {c['narrative']}")
        probes = self.next_probes()
        if probes:
            lines.append("\n## Next probes (to complete a chain)")
            for p in probes[:5]:
                lines.append(f"- toward {p['goal']}: obtain {p['missing_capability']} {p['constraints']}")
        hot = [p for p in ws.get("pinned", []) if p["type"] == "finding"][:10]
        if hot:
            lines.append("\n## Confirmed findings (pinned)")
            for p in hot:
                a = p["attrs"]
                lines.append(f"- {a.get('vuln_class', '?')} @ {a.get('host', '')}{a.get('path', '')}")
        text = self.redact("\n".join(lines))     # never leak raw secrets into a prompt
        if len(text) > budget_chars:
            text = text[:budget_chars - 3] + "..."
        return text

    def export(self) -> dict:
        """Full inspectable snapshot of the memory (for debugging/reporting)."""
        s = self.store
        return {
            "step": s.step,
            "nodes": {t: len(s.nodes_by_type(t))
                      for t in ("target", "host", "endpoint", "param", "tech",
                                "finding", "credential", "technique")},
            "chains": self.chains(),
            "next_probes": self.next_probes(),
        }
