"""
harness.classify.sklearn_model — a real, trainable CWE classifier.

This is the design's "Aota baseline" done properly: TF-IDF over the finding text
+ a multinomial Logistic Regression (chosen over LinearSVC because it emits
calibrated probabilities, which the confidence gate needs). It implements the
same `CweClassifier` interface as the keyword stub, so it drops into the exact
same pipeline — only better.

Train it on a labeled CVE->CWE corpus (JSONL of {"text","cwe","date"} — build one
from NVD, or use the RoBERTa-125M / Haddad datasets from the design §7):

    harness train --data nvd_cwe.jsonl --model model.pkl
    harness classify --classifier model.pkl

Requires scikit-learn. Persisted with stdlib pickle (no joblib dependency).
"""
from __future__ import annotations

import pickle
from typing import Any, Optional

from ..schema import ConfidenceSource, CweAssignment
from .base import CweClassifier


class SklearnCweClassifier(CweClassifier):
    name = "sklearn-tfidf-logreg"

    def __init__(self, pipeline: Any = None, labels: Optional[list[str]] = None):
        self._pipe = pipeline
        self._labels = labels or []

    # ---- training -------------------------------------------------------- #
    @classmethod
    def train(cls, texts: list[str], labels: list[str],
              min_df: int = 1, max_features: int = 50000,
              C: float = 4.0) -> "SklearnCweClassifier":
        """Fit a TF-IDF + LogisticRegression model. Returns a ready classifier."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline

        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(
                lowercase=True, ngram_range=(1, 2),
                min_df=min_df, max_features=max_features,
                sublinear_tf=True, strip_accents="unicode")),
            ("clf", LogisticRegression(
                C=C, max_iter=2000, class_weight=None)),
        ])
        pipe.fit(texts, labels)
        return cls(pipeline=pipe, labels=list(pipe.named_steps["clf"].classes_))

    # ---- prediction ------------------------------------------------------ #
    def predict(self, text: str, top_k: int = 3) -> list[CweAssignment]:
        if not text or self._pipe is None:
            return []
        probs = self._pipe.predict_proba([text])[0]
        ranked = sorted(zip(self._labels, probs), key=lambda t: t[1], reverse=True)
        out = []
        for cwe, p in ranked[:top_k]:
            if p <= 0.01:
                continue
            out.append(CweAssignment(
                cwe_id=cwe, confidence=round(float(p), 3),
                source=ConfidenceSource.MODEL,
                rationale=f"{self.name} p={p:.3f}",
            ))
        return out

    # ---- persistence ----------------------------------------------------- #
    def save(self, path: str) -> None:
        with open(path, "wb") as fh:
            pickle.dump({"pipeline": self._pipe, "labels": self._labels,
                         "name": self.name}, fh)

    @classmethod
    def load(cls, path: str) -> "SklearnCweClassifier":
        with open(path, "rb") as fh:
            blob = pickle.load(fh)        # noqa: S301 (trusted local model file)
        return cls(pipeline=blob["pipeline"], labels=blob["labels"])
