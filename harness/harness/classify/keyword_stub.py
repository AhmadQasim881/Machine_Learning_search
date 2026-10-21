"""
harness.classify.keyword_stub — the BASELINE CWE classifier.

This is a deliberately dumb, dependency-free keyword/regex matcher so the
scaffold runs end-to-end today. It is the "v0" the design calls for (Aota's
BoW+RF role) and NOTHING MORE — do not mistake its outputs for a real model's.

Confidence here is a crude, bounded heuristic (max single-pattern weight, nudged
up when several patterns for the same CWE fire). Because it rarely clears the
0.80 gate, most findings land in NEEDS_REVIEW — which is the correct, honest
default until you plug in a trained model.

UPGRADE PATH (see README):
  - drop-in a scikit-learn BoW+RandomForest (Aota) trained on NVD, or
  - the Simonetto two-step LoRA classifier, or
  - the self-hostable RoBERTa-125M CVE->CWE model + dataset (§7),
  each implemented as a CweClassifier subclass with a real .predict().
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from ..schema import ConfidenceSource, CweAssignment
from .base import CweClassifier

_DATA = os.path.join(os.path.dirname(__file__), "..", "data", "cwe_keywords.json")


class KeywordCweClassifier(CweClassifier):
    name = "keyword-stub"

    def __init__(self, data_path: str = _DATA):
        with open(data_path, "r", encoding="utf-8") as fh:
            blob: dict[str, Any] = json.load(fh)
        self.table = blob["cwes"]
        # precompile patterns
        self._compiled = []
        for entry in self.table:
            pats = [(re.compile(re.escape(p), re.IGNORECASE), float(w))
                    for p, w in entry["patterns"]]
            self._compiled.append((entry["cwe"], entry["name"], pats))

    def predict(self, text: str) -> list[CweAssignment]:
        if not text:
            return []
        out: list[CweAssignment] = []
        for cwe, name, pats in self._compiled:
            hits = [(p.pattern, w) for p, w in pats if p.search(text)]
            if not hits:
                continue
            # confidence: strongest single signal, nudged by corroboration,
            # capped below 0.95 (a keyword matcher is never certain)
            best = max(w for _, w in hits)
            corroboration = min(0.15, 0.05 * (len(hits) - 1))
            conf = min(0.95, best + corroboration)
            matched = ", ".join(sorted({h for h, _ in hits}))
            out.append(CweAssignment(
                cwe_id=cwe,
                confidence=round(conf, 3),
                source=ConfidenceSource.MODEL,
                rationale=f"keyword-stub matched: {matched}",
            ))
        return sorted(out, key=lambda c: c.confidence, reverse=True)
