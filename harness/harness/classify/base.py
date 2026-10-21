"""
harness.classify.base — the CWE classifier contract + the confidence gate.

The design (§4) says the brain is a DAG of small, individually-validated models
BEHIND CONFIDENCE GATES — never one monolithic LLM, and never an authority.
This module encodes exactly that boundary:

  * `CweClassifier` — the swappable interface. The scaffold ships a keyword
    baseline (keyword_stub.py). You replace it with a real model (Aota BoW+RF,
    Simonetto two-step, or the RoBERTa-125M repo from §7) WITHOUT touching the
    rest of the harness — same interface, better predictions.

  * `apply_gate` — the Aota rule: auto-accept the top label only when its
    confidence clears a threshold (default 0.80); otherwise route the finding
    to a human (status=NEEDS_REVIEW). The ground truth is noisy (§1: 55% of NVD
    CWE labels are invalid), so nothing is auto-accepted blindly.
"""
from __future__ import annotations

import abc

from ..schema import CweAssignment, Finding, Status


DEFAULT_GATE = 0.80   # Aota et al. C>0.8 auto-accept threshold


class CweClassifier(abc.ABC):
    """Predict CWE label(s) for a finding from its text."""

    name: str = "base"

    @abc.abstractmethod
    def predict(self, text: str) -> list[CweAssignment]:
        """Return CWE assignments sorted by descending confidence (may be empty)."""
        ...

    def classify(self, f: Finding, keep_tool_labels: bool = True) -> Finding:
        """Run prediction over a finding's classification_text and merge results.

        Tool-asserted CWEs already on the finding are kept (and can corroborate
        a model prediction) unless keep_tool_labels=False.
        """
        preds = self.predict(f.classification_text())
        merged: dict[str, CweAssignment] = {}
        if keep_tool_labels:
            for c in f.cwes:
                merged[c.cwe_id] = c
        for c in preds:
            prev = merged.get(c.cwe_id)
            # keep the higher-confidence assignment per CWE
            if prev is None or c.confidence > prev.confidence:
                merged[c.cwe_id] = c
        f.cwes = sorted(merged.values(), key=lambda c: c.confidence, reverse=True)
        return f


def apply_gate(f: Finding, threshold: float = DEFAULT_GATE) -> Finding:
    """The confidence gate. Sets overall confidence + status.

    - No CWE at all            -> NEEDS_REVIEW (human must classify)
    - top CWE confidence < T   -> NEEDS_REVIEW
    - top CWE confidence >= T   -> TRIAGED (auto-accepted suggestion)
    A human can always override; this only decides what gets queued.
    """
    top = f.top_cwe()
    if top is None:
        f.confidence = 0.0
        if f.status == Status.NEW:
            f.status = Status.NEEDS_REVIEW
        return f
    f.confidence = top.confidence
    if f.status in (Status.NEW,):
        f.status = Status.TRIAGED if top.confidence >= threshold else Status.NEEDS_REVIEW
    return f
