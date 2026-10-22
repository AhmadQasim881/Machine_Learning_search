"""
agentmem.profiles — domain profiles over one engine.

The engine (store, chains, retrieve, forget, working, security) is domain-agnostic.
A `Profile` supplies the DOMAIN knowledge: the capability ontology (what facts
provide/require), the escalation rules + goal severities, how to label a node in a
chain narrative, and a canonical-key helper. Swapping the profile retargets the
whole memory to a new domain — same graph, same chain engine.

Shipped profiles:
  - WEB  — web bug-bounty (open-redirect/IDOR/SSRF/… -> token-theft/ATO/priv-esc).
  - CODEREVIEW — source-code taint analysis (source -> propagator -> sink -> rce/
    sqli/…). Proves domain-independence: a data-flow path is the SAME capability
    chain (source `provides tainted{var}`, sink `requires tainted{var}`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from . import canonical as C
from . import capabilities as caps
from . import config


@dataclass
class Profile:
    name: str
    provides: dict          # kind -> (attrs) -> list[(token, attrs)]
    requires: dict          # kind -> (attrs) -> list[(token, attrs)]
    escalation_rules: list  # [{goal, need:[(token, attrs)]}]
    goal_severity: dict     # goal -> int
    label: Optional[Callable] = None   # (attrs, node_type) -> str
    probes: Optional[Callable] = None  # (store) -> list[dict]; overrides generic next_probes

    def label_for(self, attrs: dict, node_type: str) -> str:
        if self.label:
            return self.label(attrs, node_type)
        return attrs.get("vuln_class") or attrs.get("name") or node_type


# --------------------------------------------------------------------------- #
# WEB profile — the current web bug-bounty ontology (backed by config.py)
# --------------------------------------------------------------------------- #
def _web_label(attrs: dict, node_type: str) -> str:
    return attrs.get("vuln_class") or attrs.get("name") or node_type


WEB = Profile(
    name="web",
    provides=config.PROVIDES,
    requires=config.REQUIRES,
    escalation_rules=config.ESCALATION_RULES,
    goal_severity=config.GOAL_SEVERITY,
    label=_web_label,
)


# --------------------------------------------------------------------------- #
# CODEREVIEW profile — taint analysis on the identical engine
# --------------------------------------------------------------------------- #
# A data-flow vulnerability IS a capability chain:
#   source   provides tainted{var=a}
#   propagator  requires tainted{var=a}, provides tainted{var=b}
#   sink     requires tainted{var=b}, provides a GOAL token (by sink kind)
# A sanitizer that cleans a var simply does not re-provide its taint (breaking
# the chain). Goals map from the sink kind (sql->full_db_read, exec->rce, ...).

# sink kind -> the goal capability it yields when reached by tainted data.
_SINK_GOAL = {
    # code execution
    "exec": "rce", "command": "rce", "eval": "rce", "deserialize": "rce",
    "template": "rce",                  # server-side template injection
    "pickle": "rce",
    # databases
    "sql": "full_db_read", "nosql": "full_db_read",
    # filesystem
    "path": "file_read", "file_read": "file_read", "file_write": "file_write",
    "xxe": "file_read",
    # network / web
    "ssrf": "ssrf_exec", "open_redirect": "open_redirect", "xss": "xss_exec",
    # other injection
    "ldap": "injection", "log": "injection", "header": "injection",
    # memory safety (C/C++/native)
    "format_string": "memory_corruption", "buffer": "memory_corruption",
    "integer_overflow": "memory_corruption",
    # crypto / auth
    "crypto": "weak_crypto", "auth": "auth_bypass",
    "generic": "injection",
}

_CR_GOAL_SEVERITY = {
    "rce": 10, "memory_corruption": 9, "full_db_read": 9, "file_write": 8,
    "auth_bypass": 8, "ssrf_exec": 7, "file_read": 7, "xss_exec": 6,
    "injection": 6, "open_redirect": 5, "weak_crypto": 5,
}


def _cr_provides_source(a):
    return [("tainted", {"var": a.get("var", "*")})]


def _cr_provides_prop(a):
    return [("tainted", {"var": a.get("var_out", a.get("var", "*"))})]


def _cr_provides_sink(a):
    goal = _SINK_GOAL.get(a.get("sink_type", "generic"), "injection")
    return [(goal, {"sink": a.get("sink_type", "generic")})]


def _cr_requires_prop(a):
    return [("tainted", {"var": a.get("var_in", "*")})]


def _cr_requires_sink(a):
    return [("tainted", {"var": a.get("var", "*")})]


# a trivial escalation per goal: the sink's own provided goal token IS the goal
_CR_ESCALATION = [{"goal": g, "need": [(g, {})]} for g in _CR_GOAL_SEVERITY]


def _cr_label(attrs: dict, node_type: str) -> str:
    kind = attrs.get("kind", node_type)
    loc = attrs.get("file", "")
    if attrs.get("line"):
        loc = f"{loc}:{attrs['line']}"
    sym = attrs.get("symbol") or attrs.get("var", "")
    return f"{kind}({sym})" + (f" @ {loc}" if loc else "")


def _cr_probes(store) -> list:
    """Taint-specific next probes. The generic goal-escalation enumeration is
    meaningless for taint (every goal that no sink has reached shows up as 'obtain
    X'). What a reviewer actually needs is the data-flow GAP to trace next:

      * DANGLING SINK  — a sink consumes a value with no recorded tainted origin:
        trace backward (highest value: the sink is where damage lands).
      * DANGLING SOURCE — untrusted input not yet traced to any sink: trace forward.
      * ORPHAN FLOW    — a propagator whose input has no tainted origin yet.

    Computed from the provides/requires tables directly (always current — set at
    write time), so it does not depend on a chain-detection pass having run."""
    nodes, all_provided, all_required = [], [], []
    for row in store.nodes_by_type("finding"):
        a = store.node_attrs(row["id"])
        kind = a.get("kind", "")
        if not kind.startswith("taint_"):
            continue
        prov, req = store.get_provides(row["id"]), store.get_requires(row["id"])
        all_provided.extend(prov)
        all_required.extend(req)
        nodes.append((kind, a, prov, req))

    out = []
    for kind, a, prov, req in nodes:
        loc = f"{a.get('file', '?')}:{a.get('line', 0)}"
        var = a.get("var") or a.get("var_in") or "?"
        if kind == "taint_sink":
            if not any(caps.any_unifies(all_provided, r) for r in req):
                st = a.get("sink_type", "generic")
                goal = _SINK_GOAL.get(st, "injection")
                out.append({
                    "goal": goal, "severity": _CR_GOAL_SEVERITY.get(goal, 6),
                    "missing_capability": f"tainted origin of '{var}'",
                    "constraints": {"file": a.get("file", ""), "line": a.get("line", 0),
                                    "var": var, "sink_type": st},
                    "suggestion": (f"DANGLING SINK: {st} sink at {loc} consumes '{var}', but no "
                                   f"tainted origin for '{var}' is recorded. Trace '{var}' backward: "
                                   f"if it derives from untrusted input, record the source + each flow "
                                   f"(this would complete a {goal} chain)."),
                })
        elif kind == "taint_source":
            if not any(caps.unify(p, r) for p in prov for r in all_required):
                out.append({
                    "goal": "trace_forward", "severity": 5,
                    "missing_capability": f"a flow/sink consuming tainted '{var}'",
                    "constraints": {"file": a.get("file", ""), "line": a.get("line", 0), "var": var},
                    "suggestion": (f"DANGLING SOURCE: untrusted '{var}' enters at {loc} but is not yet "
                                   f"traced to any sink. Follow where '{var}' flows (assignments, "
                                   f"calls, concatenations) and record each flow, then the sink it reaches."),
                })
        elif kind == "taint_prop":
            if not any(caps.any_unifies(all_provided, r) for r in req):
                out.append({
                    "goal": "trace_backward", "severity": 4,
                    "missing_capability": f"tainted origin of '{var}'",
                    "constraints": {"file": a.get("file", ""), "line": a.get("line", 0), "var": var},
                    "suggestion": (f"ORPHAN FLOW: the flow at {loc} carries '{var}', but nothing yet "
                                   f"produces tainted '{var}'. Trace '{var}' back to its origin."),
                })
    out.sort(key=lambda d: d["severity"], reverse=True)
    return out


CODEREVIEW = Profile(
    name="codereview",
    provides={
        "taint_source": _cr_provides_source,
        "taint_prop": _cr_provides_prop,
        "taint_sink": _cr_provides_sink,
        # a sanitizer is INERT in the engine: it provides no taint token, so a
        # cleaned value simply does not propagate (the correct, negation-free way
        # to break a chain). Recorded only for the portrait / audit trail.
        "taint_sanitizer": lambda a: [],
    },
    requires={
        "taint_prop": _cr_requires_prop,
        "taint_sink": _cr_requires_sink,
        "taint_sanitizer": lambda a: [],
    },
    escalation_rules=_CR_ESCALATION,
    goal_severity=_CR_GOAL_SEVERITY,
    label=_cr_label,
    probes=_cr_probes,
)


def cr_key(kind: str, file: str, symbol: str = "", var: str = "", line: int = 0) -> str:
    """Canonical key for a code-review fact (file + symbol/var + line)."""
    return C._key("cr", kind, (file or "").lower(), symbol or "", var or "", str(line or 0))


def get(name: str) -> Profile:
    return {"web": WEB, "codereview": CODEREVIEW}.get(name, WEB)
