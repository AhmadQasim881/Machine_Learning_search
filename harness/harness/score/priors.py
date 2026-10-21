"""
harness.score.priors — a Miyamoto-style CWE -> CVSS v3.1 vector PRIOR table.

The design (§Group D, Miyamoto) uses a near-deterministic CWE->CVSS base-metric
prior to SEED a vector when none is predicted/known, and as a cross-check. This
is a small, honest, hand-built table for common web CWEs — NOT a learned model
and NOT authoritative: it is written with low per-metric confidence so the
subjective metrics (PR/C/I/A) route to a human (design: "always route PR + C/I/A
to a human"). Rebuild on current NVD for production use.

Returns a bare vector (no "CVSS:3.1/" prefix), matching CvssScore.vector.
"""
from __future__ import annotations

from typing import Optional

# bare v3.1 base vectors — deliberately conservative; treat as a seed, not truth
_PRIORS: dict[str, str] = {
    "CWE-79":   "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # reflected XSS
    "CWE-89":   "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # SQLi
    "CWE-918":  "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",   # SSRF
    "CWE-22":   "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",   # path traversal
    "CWE-352":  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",   # CSRF
    "CWE-78":   "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",   # OS command injection
    "CWE-94":   "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",   # code injection
    "CWE-1336": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",   # SSTI
    "CWE-601":  "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",   # open redirect
    "CWE-611":  "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",   # XXE
    "CWE-287":  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # improper auth
    "CWE-502":  "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",   # insecure deserialization
    "CWE-200":  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # info exposure
    "CWE-434":  "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",   # unrestricted upload
    "CWE-306":  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # missing auth
    "CWE-798":  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # hard-coded creds
}

# the subjective metrics the design insists a human confirms
SUBJECTIVE = ["PR", "S", "C", "I", "A"]


def prior_vector(cwe_id: str) -> Optional[str]:
    """Bare CVSS v3.1 vector seed for a CWE, or None if no prior is known."""
    return _PRIORS.get((cwe_id or "").upper())


def low_confidence_for_subjective() -> dict[str, float]:
    """Per-metric confidence to attach to a prior-seeded vector: low on the
    subjective metrics so they route to human review."""
    return {m: 0.3 for m in SUBJECTIVE}
