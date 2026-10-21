"""
harness.ingest.nuclei — adapter for nuclei JSONL output.

Run nuclei with `-jsonl` (one JSON object per line) and feed the file here:

    nuclei -u https://target -jsonl -o out.jsonl
    harness ingest --tool nuclei --file out.jsonl --program acme

We map nuclei's native fields onto the 9-aspect spine and pre-seed CWE/CVSS
from nuclei's own `info.classification` when present (source=TOOL, so the
confidence gate still lets the model/human revise it).
"""
from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse

from ..schema import (ConfidenceSource, CvssScore, CweAssignment, Finding)
from .base import Adapter, register


def _sev_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


@register("nuclei")
class NucleiAdapter(Adapter):

    def parse(self, raw_text: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(raw_text.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(self._one(rec, i))
        return findings

    def _one(self, rec: dict[str, Any], idx: int) -> Finding:
        info = rec.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        matched = rec.get("matched-at") or rec.get("host") or ""
        parsed = urlparse(matched if "://" in matched else f"//{matched}")

        f = Finding(
            source_tool="nuclei",
            source_ref=rec.get("template-id", f"line:{idx}"),
            url=matched,
            host=parsed.hostname or rec.get("host", ""),
            port=parsed.port,
            vuln_type=info.get("name", ""),
            title=info.get("name", ""),
            description=info.get("description", "") or info.get("name", ""),
            attack_vector=rec.get("matched-at", ""),
            severity=(info.get("severity", "") or "").capitalize(),
            evidence=[e for e in [rec.get("curl-command"),
                                  rec.get("extracted-results") and
                                  json.dumps(rec.get("extracted-results"))]
                      if e],
            tags=list(info.get("tags", []) or []),
        )

        # pre-seed CWE from nuclei's classification (tool-asserted)
        for cwe in _as_list(classification.get("cwe-id")):
            cid = _canon_cwe(cwe)
            if cid:
                f.cwes.append(CweAssignment(
                    cwe_id=cid, confidence=0.5,
                    source=ConfidenceSource.TOOL,
                    rationale="nuclei template classification",
                ))

        # pre-seed CVSS from nuclei's classification (tool-asserted)
        vector = classification.get("cvss-metrics", "")
        score = classification.get("cvss-score")
        if vector or score is not None:
            f.cvss = CvssScore(
                version="3.1" if vector.startswith("CVSS:3") else "3.1",
                vector=vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", ""),
                base_score=float(score) if score is not None else None,
                severity=_sev_from_cvss(float(score)) if score is not None else f.severity,
                source=ConfidenceSource.TOOL,
            )
            if not f.severity and f.cvss.severity:
                f.severity = f.cvss.severity
        return f


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _canon_cwe(raw: str) -> str:
    """Normalize 'cwe-79' / '79' / 'CWE-79' -> 'CWE-79'."""
    s = str(raw).strip().upper().replace("CWE-", "").replace("CWE", "")
    s = s.strip("- ")
    return f"CWE-{s}" if s.isdigit() else ""
