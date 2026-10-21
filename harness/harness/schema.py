"""
harness.schema — the single finding record that flows through every stage.

Design source: §3 of the research guide. The record is the Sun et al. 9-aspect
schema (the ingest normalization spine) plus the fields each later stage writes:
CWE (multi-label), CVSS, exploit-likelihood, cluster id, triage confidence,
status, evidence, and the Stage-0 authorization block.

Deliberately dependency-free: stdlib dataclasses + enums only, so the scaffold
runs on a bare Python 3.9+ install. Every object is JSON-round-trippable via
`to_dict()` / `from_dict()`, which is also how it is persisted (see store.py).

Why multi-label CWE: every classifier in the downloaded corpus forces a single
label, but real findings are often multi-weakness (§4 failure modes, and the
CVE-LMTune multi-taxonomy paper in §7). The record holds a LIST of CWE
assignments so the harness is never more brittle than the models it wraps.
"""
from __future__ import annotations

import enum
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Status(str, enum.Enum):
    """Triage lifecycle of a finding. Ordered roughly by progression."""
    NEW = "new"                       # just ingested, nothing enriched yet
    NEEDS_REVIEW = "needs_review"     # a confidence gate sent it to a human
    TRIAGED = "triaged"               # enriched + auto-accepted by the gates
    VALIDATED = "validated"           # confirmed real (PoC / oracle / human)
    DUPLICATE = "duplicate"           # collapsed into another finding
    FALSE_POSITIVE = "false_positive"
    REPORTED = "reported"             # submitted to the program
    ACCEPTED = "accepted"             # program accepted it
    REJECTED = "rejected"             # program rejected it
    REMEDIATED = "remediated"


class ConfidenceSource(str, enum.Enum):
    TOOL = "tool"        # the scanner asserted it (e.g. nuclei classification)
    MODEL = "model"      # an ML model predicted it
    HUMAN = "human"      # an analyst confirmed/overrode it
    PRIOR = "prior"      # a heuristic/lookup table (e.g. CWE->CVSS prior)


# --------------------------------------------------------------------------- #
# Sub-objects
# --------------------------------------------------------------------------- #
@dataclass
class CweAssignment:
    """One CWE label on a finding. A finding may carry several."""
    cwe_id: str                       # canonical form "CWE-79"
    confidence: float = 0.0           # 0..1
    source: ConfidenceSource = ConfidenceSource.MODEL
    rationale: str = ""               # short, human-readable justification

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CweAssignment":
        return cls(
            cwe_id=d["cwe_id"],
            confidence=float(d.get("confidence", 0.0)),
            source=ConfidenceSource(d.get("source", "model")),
            rationale=d.get("rationale", ""),
        )


@dataclass
class CvssScore:
    """A CVSS assessment. Predict the vector, then compute the score with the
    official equations (§4 thesis 3) — never let a model emit the number."""
    version: str = "3.1"              # "2.0" | "3.0" | "3.1" | "4.0"
    vector: str = ""                  # e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    base_score: Optional[float] = None
    severity: str = ""                # None/Low/Medium/High/Critical
    per_metric_confidence: dict[str, float] = field(default_factory=dict)
    source: ConfidenceSource = ConfidenceSource.MODEL

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CvssScore":
        return cls(
            version=d.get("version", "3.1"),
            vector=d.get("vector", ""),
            base_score=d.get("base_score"),
            severity=d.get("severity", ""),
            per_metric_confidence=d.get("per_metric_confidence", {}) or {},
            source=ConfidenceSource(d.get("source", "model")),
        )


@dataclass
class Exploit:
    """Validation + exploit-likelihood signals (Stages 3 and 7)."""
    poc_path: str = ""                # path to a stored, NON-DESTRUCTIVE PoC
    poc_verified: bool = False        # confirmed to reproduce (sandbox/oracle)
    exploit_likelihood: Optional[float] = None   # P(exploited) 0..1 (EPSS-style)
    likelihood_source: str = ""       # "epss" | "kev" | "model:fastembed" | ...

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Exploit":
        return cls(
            poc_path=d.get("poc_path", ""),
            poc_verified=bool(d.get("poc_verified", False)),
            exploit_likelihood=d.get("exploit_likelihood"),
            likelihood_source=d.get("likelihood_source", ""),
        )


@dataclass
class Authorization:
    """Stage-0 gate. A finding is only actionable if BOTH scope and rules of
    engagement are satisfied. Scope alone is NOT authorization (§3, §6)."""
    program: str = ""
    in_scope: bool = False            # the asset is on the program allow-list
    roe_ok: bool = False              # allowed tool + rate + technique
    authorized_by: str = ""           # who/what confirmed authorization
    notes: str = ""

    @property
    def actionable(self) -> bool:
        return self.in_scope and self.roe_ok

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Authorization":
        return cls(
            program=d.get("program", ""),
            in_scope=bool(d.get("in_scope", False)),
            roe_ok=bool(d.get("roe_ok", False)),
            authorized_by=d.get("authorized_by", ""),
            notes=d.get("notes", ""),
        )


# --------------------------------------------------------------------------- #
# The finding record
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """One normalized finding. The spine of the whole pipeline."""
    # identity / provenance
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_tool: str = ""             # "nuclei", "burp", "manual", ...
    source_ref: str = ""              # pointer back to the raw record/line

    # target location
    url: str = ""
    host: str = ""
    port: Optional[int] = None
    param: str = ""                   # the vulnerable parameter, if any

    # Sun et al. 9-aspect schema (the normalization spine)
    vendor: str = ""
    product: str = ""
    version: str = ""
    component: str = ""
    vuln_type: str = ""
    root_cause: str = ""
    impact: str = ""
    attacker_type: str = ""
    attack_vector: str = ""

    # free text used by the brain
    title: str = ""
    description: str = ""

    # enrichment written by later stages
    cwes: list[CweAssignment] = field(default_factory=list)      # Stage 5
    cvss: Optional[CvssScore] = None                             # Stage 6
    exploit: Exploit = field(default_factory=Exploit)            # Stages 3/7

    # triage bookkeeping
    confidence: float = 0.0           # overall triage confidence (0..1)
    status: Status = Status.NEW
    severity: str = ""                # convenience mirror of cvss.severity
    cluster_id: str = ""              # Stage 4 dedup/cluster membership
    dedup_key: str = ""              # cheap exact-dup key (see store.dedup_key)
    priority_score: Optional[float] = None   # Stage 7 ranking key
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # authorization (Stage 0)
    authorization: Authorization = field(default_factory=Authorization)

    # timestamps
    discovered_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    # ---- the text the brain actually classifies -------------------------- #
    def classification_text(self) -> str:
        """The blob fed to CWE/CVSS models. Prefer a rich description; fall
        back to assembling the 9-aspect fields + title."""
        if self.description.strip():
            base = self.description
        else:
            parts = [self.title, self.vuln_type, self.root_cause,
                     self.impact, self.attack_vector, self.product]
            base = " ".join(p for p in parts if p)
        return base.strip()

    def top_cwe(self) -> Optional[CweAssignment]:
        if not self.cwes:
            return None
        return max(self.cwes, key=lambda c: c.confidence)

    def touch(self) -> None:
        self.updated_at = _now()

    # ---- serialization --------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_tool": self.source_tool,
            "source_ref": self.source_ref,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "param": self.param,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "component": self.component,
            "vuln_type": self.vuln_type,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "attacker_type": self.attacker_type,
            "attack_vector": self.attack_vector,
            "title": self.title,
            "description": self.description,
            "cwes": [c.to_dict() for c in self.cwes],
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "exploit": self.exploit.to_dict(),
            "confidence": self.confidence,
            "status": self.status.value,
            "severity": self.severity,
            "cluster_id": self.cluster_id,
            "dedup_key": self.dedup_key,
            "priority_score": self.priority_score,
            "evidence": list(self.evidence),
            "tags": list(self.tags),
            "authorization": self.authorization.to_dict(),
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        f = cls(
            id=d.get("id") or str(uuid.uuid4()),
            source_tool=d.get("source_tool", ""),
            source_ref=d.get("source_ref", ""),
            url=d.get("url", ""),
            host=d.get("host", ""),
            port=d.get("port"),
            param=d.get("param", ""),
            vendor=d.get("vendor", ""),
            product=d.get("product", ""),
            version=d.get("version", ""),
            component=d.get("component", ""),
            vuln_type=d.get("vuln_type", ""),
            root_cause=d.get("root_cause", ""),
            impact=d.get("impact", ""),
            attacker_type=d.get("attacker_type", ""),
            attack_vector=d.get("attack_vector", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            confidence=float(d.get("confidence", 0.0)),
            status=Status(d.get("status", "new")),
            severity=d.get("severity", ""),
            cluster_id=d.get("cluster_id", ""),
            dedup_key=d.get("dedup_key", ""),
            priority_score=d.get("priority_score"),
            evidence=list(d.get("evidence", []) or []),
            tags=list(d.get("tags", []) or []),
            discovered_at=d.get("discovered_at") or _now(),
            updated_at=d.get("updated_at") or _now(),
        )
        f.cwes = [CweAssignment.from_dict(c) for c in d.get("cwes", []) or []]
        f.cvss = CvssScore.from_dict(d["cvss"]) if d.get("cvss") else None
        f.exploit = Exploit.from_dict(d.get("exploit", {}) or {})
        f.authorization = Authorization.from_dict(d.get("authorization", {}) or {})
        return f

    @classmethod
    def from_json(cls, s: str) -> "Finding":
        return cls.from_dict(json.loads(s))
