"""
harness.score.cvss31 — a correct, dependency-free CVSS v3.1 BASE score calculator.

Design principle (§4): never let a model emit the CVSS number. A model predicts
the VECTOR (per-metric); this module turns that vector into the score with the
official FIRST.org v3.1 equations and roundup function. Offline, stdlib only.

Only BASE metrics are implemented (Temporal/Environmental and v4.0 are gaps
flagged in the design). Validated against published vectors in the tests.

Reference: FIRST CVSS v3.1 Specification, section 7.1.
"""
from __future__ import annotations

import math
from typing import Optional

# metric value weights -------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

# the legal values per metric key (for validation / model output constraints)
CVSS31_METRICS = {
    "AV": list("NALP"), "AC": list("LH"), "PR": list("NLH"), "UI": list("NR"),
    "S": list("UC"), "C": list("HLN"), "I": list("HLN"), "A": list("HLN"),
}
_REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def parse_vector(vector: str) -> dict[str, str]:
    """Parse 'CVSS:3.1/AV:N/AC:L/...' or the bare 'AV:N/AC:L/...' into a dict.

    Raises ValueError if a required base metric is missing or a value is illegal.
    """
    v = vector.strip()
    parts = [p for p in v.split("/") if p]
    out: dict[str, str] = {}
    for p in parts:
        if ":" not in p:
            continue
        k, _, val = p.partition(":")
        k, val = k.strip().upper(), val.strip().upper()
        if k in ("CVSS",):
            continue
        if k in CVSS31_METRICS:
            if val not in CVSS31_METRICS[k]:
                raise ValueError(f"illegal value {k}:{val}")
            out[k] = val
    missing = [m for m in _REQUIRED if m not in out]
    if missing:
        raise ValueError(f"missing required base metrics: {missing}")
    return out


def _roundup(x: float) -> float:
    """The CVSS v3.1 roundup: round UP to 1 decimal place, avoiding FP error."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS v3.1 base score (0.0..10.0) from a parsed metrics dict."""
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
                      * pr_table[metrics["PR"]] * _UI[metrics["UI"]])

    if impact <= 0:
        return 0.0
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_of(score: Optional[float]) -> str:
    """CVSS v3.1 qualitative severity rating."""
    if score is None:
        return ""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def score_vector(vector: str) -> tuple[float, str]:
    """Convenience: vector string -> (base_score, severity)."""
    m = parse_vector(vector)
    s = base_score(m)
    return s, severity_of(s)
