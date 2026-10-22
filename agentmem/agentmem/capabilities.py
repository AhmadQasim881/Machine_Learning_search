"""
agentmem.capabilities — the capability (precondition -> postcondition) model.

This is the core of chain detection (spec §4.1). Every Finding declares what it
`provides` and `requires` as structured capability TOKENS, and two findings link
(`A ENABLES B`) iff some token in A.provides UNIFIES with some token in
B.requires. Unification connects facts that look nothing alike to an embedding
model — an open-redirect's `controlled_redirect` unifies with an OAuth endpoint's
`requires: controlled_redirect` — which is exactly what finds exploit chains.

A token is `(name, attrs)` where attrs is a dict. On the REQUIRES side an attr
value may be:
  - "*" or missing  -> matches anything
  - "in:<glob>"     -> membership/pattern constraint (fnmatch), e.g. "in:*.target.com"
  - a concrete value -> must equal the provided value (or provided "*")
On the PROVIDES side attrs are concrete, or "*" meaning "attacker-controlled".
"""
from __future__ import annotations

import json
from fnmatch import fnmatchcase
from typing import Optional

from . import config

Token = tuple[str, dict]


# --- building capabilities for a finding ----------------------------------- #
def capabilities_for(vuln_class: str, attrs: dict) -> tuple[list[Token], list[Token]]:
    """Return (provides, requires) token lists for a finding of this vuln_class."""
    prov = config.PROVIDES.get(vuln_class, lambda a: [])(attrs)
    req = config.REQUIRES.get(vuln_class, lambda a: [])(attrs)
    return prov, req


# --- unification ----------------------------------------------------------- #
def _attr_ok(provided, required) -> bool:
    if required in (None, "*"):
        return True
    if isinstance(required, str) and required.startswith("in:"):
        pattern = required[3:]
        if provided is None:
            return False
        # case-insensitive + platform-independent (fnmatch uses os.path.normcase,
        # which is identity on Linux but lowercases on Windows -> non-determinism)
        return provided == "*" or fnmatchcase(str(provided).lower(), pattern.lower())
    if provided is None:
        return False
    return provided == required or provided == "*"


def unify(provide: Token, require: Token) -> Optional[dict]:
    """If `provide` satisfies `require`, return a binding dict (the concrete
    provided attrs); else None. Names must match and every required attr must be
    satisfiable by the provided attrs."""
    pname, pattrs = provide
    rname, rattrs = require
    if pname != rname:
        return None
    for k, rv in (rattrs or {}).items():
        if not _attr_ok(pattrs.get(k), rv):
            return None
    binding = {k: v for k, v in (pattrs or {}).items() if v != "*"}
    return binding


def any_unifies(provides: list[Token], require: Token) -> Optional[dict]:
    for p in provides:
        b = unify(p, require)
        if b is not None:
            return b
    return None


# --- escalation: does an accumulated capability set reach a GOAL? ----------- #
def reached_goals(available: list[Token]) -> list[tuple[str, int]]:
    """Return [(goal, severity)] for every escalation rule whose `need` tokens
    are all satisfied by the available provided tokens."""
    out = []
    for rule in config.ESCALATION_RULES:
        if all(any_unifies(available, need) is not None for need in rule["need"]):
            goal = rule["goal"]
            out.append((goal, config.GOAL_SEVERITY.get(goal, 5)))
    return out


# --- (de)serialization helpers for the provides/requires tables ------------ #
def dump_attrs(attrs: dict) -> str:
    # canonical JSON so the (node_id, token, attrs_json) PK is stable
    return json.dumps(attrs or {}, sort_keys=True, separators=(",", ":"))


def load_token(token: str, attrs_json: str) -> Token:
    try:
        return (token, json.loads(attrs_json or "{}"))
    except json.JSONDecodeError:
        return (token, {})
