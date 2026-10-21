"""
harness.prioritize — Stage 7, a TRANSPARENT finding-level priority score.

The design is explicit: CVSS is severity, not risk; real prioritization fuses
severity with exploit likelihood (EPSS), in-the-wild confirmation (KEV), and
finding-level evidence (a verified PoC) — and it must expose its breakdown so an
analyst can see WHY something ranked where it did (no black-box ranking).

This is deliberately a simple, legible linear blend with a KEV override, not a
learned model. It is the SCAFFOLD for the real finding-level exploit-likelihood
model (your IP): swap `score()` for a trained estimator later; keep the
breakdown contract so the UI/report don't change.

    priority = 100 * ( w_cvss*cvss_norm + w_epss*epss + bonus_poc )   # 0..~100
    if KEV:   priority = max(priority, KEV_FLOOR)   # known-exploited floats up
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .schema import Finding

# weights — tune to your program's appetite; they are intentionally visible
W_CVSS = 0.55
W_EPSS = 0.35
BONUS_POC = 0.10          # a reproduced PoC is strong finding-level evidence
KEV_FLOOR = 90.0          # anything known-exploited ranks near the top


@dataclass
class PriorityResult:
    score: float
    breakdown: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


def _cvss_norm(f: Finding) -> float:
    if f.cvss and f.cvss.base_score is not None:
        return max(0.0, min(1.0, f.cvss.base_score / 10.0))
    # fall back to qualitative severity if no numeric score
    return {"critical": 0.95, "high": 0.75, "medium": 0.5,
            "low": 0.2, "none": 0.0}.get((f.severity or "").lower(), 0.0)


def score(f: Finding, epss: Optional[float] = None, in_kev: bool = False) -> PriorityResult:
    """Compute a priority score for one finding. `epss` and `in_kev` come from the
    enrichment feeds (pass them in so this stays pure/testable)."""
    cvss_n = _cvss_norm(f)
    epss_v = max(0.0, min(1.0, epss if epss is not None else 0.0))
    poc = BONUS_POC if f.exploit.poc_verified else 0.0

    raw = W_CVSS * cvss_n + W_EPSS * epss_v + poc
    s = round(100.0 * raw, 1)

    reasons = []
    if cvss_n:
        reasons.append(f"CVSS {f.cvss.base_score if f.cvss else f.severity}")
    if epss is not None:
        reasons.append(f"EPSS {epss_v:.1%}")
    if f.exploit.poc_verified:
        reasons.append("verified PoC (+)")

    if in_kev:
        s = max(s, KEV_FLOOR)
        reasons.append("CISA KEV — known exploited (floor)")

    return PriorityResult(
        score=s,
        breakdown={"cvss_norm": round(cvss_n, 3), "epss": round(epss_v, 3),
                   "poc_bonus": poc, "kev_floor_applied": float(in_kev)},
        reasons=reasons,
    )


def apply(f: Finding, epss: Optional[float] = None, in_kev: bool = False) -> PriorityResult:
    """Score and write priority_score back onto the finding."""
    res = score(f, epss=epss, in_kev=in_kev)
    f.priority_score = res.score
    if "kev" not in [t.lower() for t in f.tags] and in_kev:
        f.tags.append("kev")
    return res
