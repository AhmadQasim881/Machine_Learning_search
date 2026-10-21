"""
harness.export.defectdojo — emit findings in DefectDojo's "Generic Findings
Import" JSON format.

The design recommends ADOPTING OWASP DefectDojo as the datastore/dedup/report
backbone (stages 4-8) and running this harness as the enrichment "brain" on top.
This exporter is the seam: it turns our enriched Finding records into the JSON
DefectDojo's generic importer accepts, so you upload them (UI or API) and let
DefectDojo own dedup, triage workflow, and reporting.

Format ref: DefectDojo "Generic Findings Import" (a top-level {"findings":[...]}).
We map our enrichment (CWE, CVSS vector, priority, EPSS/KEV tags) onto its fields.
Pure stdlib; no DefectDojo dependency. Pushing over REST is left to you (keeps
credentials out of the harness) — see README.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from ..schema import Finding

_SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "none": "Info", "": "Info"}


def _cwe_number(f: Finding) -> int:
    top = f.top_cwe()
    if not top:
        return 0
    try:
        return int(top.cwe_id.replace("CWE-", ""))
    except ValueError:
        return 0


def to_defectdojo_generic(findings: Iterable[Finding]) -> dict[str, Any]:
    """Return a dict ready to json.dump as a DefectDojo generic-import file."""
    out = []
    for f in findings:
        top = f.top_cwe()
        desc_lines = [f.description or f.vuln_type or f.title]
        if f.url:
            desc_lines.append(f"\nURL: {f.url}")
        if top:
            desc_lines.append(f"CWE: {top.cwe_id} (confidence {top.confidence:.2f}, "
                              f"{top.source.value})")
        if f.exploit.exploit_likelihood is not None:
            desc_lines.append(f"EPSS: {f.exploit.exploit_likelihood:.1%} "
                              f"({f.exploit.likelihood_source})")
        if f.priority_score is not None:
            desc_lines.append(f"Harness priority: {f.priority_score}")

        item: dict[str, Any] = {
            "title": f.title or f.vuln_type or "Finding",
            "description": "\n".join(desc_lines),
            "severity": _SEV_MAP.get((f.severity or "").lower(), "Info"),
            "date": (f.discovered_at or "")[:10] or None,
            "cwe": _cwe_number(f),
            "unique_id_from_tool": f.id,
            "vuln_id_from_tool": f.source_ref,
            "service": f.host,
            "dynamic_finding": True,
            "static_finding": False,
            "active": f.status.value not in ("false_positive", "duplicate", "remediated"),
            "false_p": f.status.value == "false_positive",
            "duplicate": f.status.value == "duplicate",
            "tags": list(f.tags) + ([f"tool:{f.source_tool}"] if f.source_tool else []),
        }
        if f.cvss and f.cvss.vector:
            # DefectDojo accepts a cvssv3 vector string
            item["cvssv3"] = (f.cvss.vector if f.cvss.vector.startswith("CVSS:")
                              else f"CVSS:3.1/{f.cvss.vector}")
            if f.cvss.base_score is not None:
                item["cvssv3_score"] = f.cvss.base_score
        if f.url:
            item["url"] = f.url
        out.append(item)
    return {"findings": out}


def write_defectdojo_generic(findings: Iterable[Finding], path: str) -> int:
    payload = to_defectdojo_generic(findings)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return len(payload["findings"])
