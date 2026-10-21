"""
harness.ingest.generic — a config-mapped adapter for arbitrary JSON.

For a tool without a dedicated adapter, point this at a JSON array (or JSONL)
and describe which keys map to which Finding fields. Useful for manual findings
and quick one-off tools. Dedicated adapters (like nuclei) are preferred when a
tool is used often.

Mapping is a flat dict {finding_field: source_key}. Nested keys use dots:
    {"title": "info.name", "host": "target.host"}
"""
from __future__ import annotations

import json
from typing import Any

from ..schema import Finding
from .base import Adapter, register

# a reasonable default mapping for hand-written findings
DEFAULT_MAP = {
    "title": "title",
    "description": "description",
    "url": "url",
    "host": "host",
    "param": "param",
    "vuln_type": "vuln_type",
    "severity": "severity",
    "product": "product",
    "version": "version",
}


def _dig(rec: dict[str, Any], dotted: str) -> Any:
    cur: Any = rec
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


@register("generic")
class GenericAdapter(Adapter):

    def __init__(self, mapping: dict[str, str] | None = None):
        self.mapping = mapping or DEFAULT_MAP

    def parse(self, raw_text: str) -> list[Finding]:
        raw_text = raw_text.strip()
        if not raw_text:
            return []
        # accept either a JSON array or JSONL
        records: list[dict[str, Any]]
        if raw_text[0] == "[":
            records = json.loads(raw_text)
        else:
            records = [json.loads(ln) for ln in raw_text.splitlines() if ln.strip()]

        findings = []
        for i, rec in enumerate(records):
            kwargs: dict[str, Any] = {"source_tool": rec.get("source_tool", "generic"),
                                      "source_ref": rec.get("id", f"rec:{i}")}
            for field_name, src_key in self.mapping.items():
                val = _dig(rec, src_key)
                if val is not None:
                    kwargs[field_name] = val if isinstance(val, (str, int)) else str(val)
            findings.append(Finding(**kwargs))
        return findings
