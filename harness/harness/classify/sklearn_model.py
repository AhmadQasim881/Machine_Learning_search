"""
harness.classify.sklearn_model — a real, trainable CWE classifier.

An Aota-STYLE CPU baseline — TF-IDF over the finding text + a multinomial
Logistic Regression standing in for Aota's BoW+Random-Forest role (LogReg is
chosen over LinearSVC because it emits calibrated probabilities, which the
confidence gate needs). It implements the same `CweClassifier` interface as the
keyword stub, so it drops into the exact same pipeline — only better.

Train it on a labeled CVE->CWE corpus (JSONL of {"text","cwe","date"} — build one
from NVD, or use the RoBERTa-125M / Haddad datasets from the design §7):

    harness train --data nvd_cwe.jsonl --model model.pkl
    harness classify --classifier model.pkl

SECURITY: the model is persisted with pickle, so loading an UNTRUSTED .pkl can
execute arbitrary code. Only load `--classifier` files you trained yourself or
whose provenance you trust. `save()` writes a `<model>.sha256` sidecar and
`load()` verifies it, which catches accidental corruption/swap (not a determined
attacker who controls both files) and emits a warning so the trust decision is
never silent. Requires scikit-learn.
"""
from __future__ import annotations

import hashlib
import os
import pickle
import sys
import warnings
from typing import Any, Optional

from ..schema import ConfidenceSource, CweAssignment
from .base import CweClassifier

SEED = 0   # pin training for reproducibility


class SklearnCweClassifier(CweClassifier):
    name = "sklearn-tfidf-logreg"

    def __init__(self, pipeline: Any = None, labels: Optional[list[str]] = None):
        self._pipe = pipeline
        self._labels = labels or []

    @property
    def labels(self) -> list[str]:
        """The CWE classes this model can emit (public accessor)."""
        return list(self._labels)

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
                C=C, max_iter=2000, class_weight=None, random_state=SEED)),
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
        """Pickle the model and write a `<path>.sha256` integrity sidecar."""
        payload = pickle.dumps({"pipeline": self._pipe, "labels": self._labels,
                                "name": self.name})
        with open(path, "wb") as fh:
            fh.write(payload)
        with open(path + ".sha256", "w", encoding="utf-8") as fh:
            fh.write(hashlib.sha256(payload).hexdigest())

    @classmethod
    def load(cls, path: str) -> "SklearnCweClassifier":
        """Load a model. WARNING: unpickling runs code — only load TRUSTED files.

        Verifies the `<path>.sha256` sidecar when present (catches corruption or a
        swapped file) and always warns that the load is a trust decision.
        """
        with open(path, "rb") as fh:
            payload = fh.read()
        sidecar = path + ".sha256"
        if os.path.exists(sidecar):
            with open(sidecar, encoding="utf-8") as fh:
                expected = fh.read().strip()
            actual = hashlib.sha256(payload).hexdigest()
            if actual != expected:
                raise ValueError(
                    f"model integrity check FAILED for {path}: sha256 {actual} "
                    f"!= expected {expected}. Refusing to load a tampered/corrupt model.")
        else:
            warnings.warn(f"no integrity sidecar for {path}; cannot verify it is "
                          "unmodified", stacklevel=2)
        print(f"[security] loading pickled model '{path}' — only do this for models "
              "you trained or trust (unpickling can execute code).", file=sys.stderr)
        blob = pickle.loads(payload)      # noqa: S301 — trust gated above + warned
        return cls(pipeline=blob["pipeline"], labels=blob["labels"])
