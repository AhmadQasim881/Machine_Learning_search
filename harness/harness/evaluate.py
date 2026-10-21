"""
harness.evaluate — honest, TEMPORAL-split evaluation of the CWE classifier.

This is the design's flagged differentiator (§7): every CWE/CVSS paper and repo
in the survey inflates its numbers with RANDOM splits; the real world is
forward-in-time (you train on past CVEs and classify future ones). This module
evaluates the way the design demands:

  - sort the labeled corpus by date, train on the earliest `train_frac`, test on
    the rest (a temporal hold-out) — never a random shuffle;
  - report macro-F1 (not bare accuracy), weighted-F1, overall accuracy, and the
    most-confused class pairs;
  - optionally report the gate's effect: at threshold T, what fraction auto-
    accepts and what the accuracy is on just those.

Requires scikit-learn. Returns a plain dict so the CLI can print or save it.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Optional


def temporal_split(rows: list[dict], train_frac: float = 0.8
                   ) -> tuple[list[dict], list[dict]]:
    """Sort by 'date' (ISO string; missing dates sort first) and split by time."""
    ordered = sorted(rows, key=lambda r: r.get("date") or "")
    cut = max(1, int(len(ordered) * train_frac))
    return ordered[:cut], ordered[cut:]


def evaluate(rows: list[dict], train_frac: float = 0.8,
             gate: float = 0.80) -> dict[str, Any]:
    """rows: [{"text","cwe","date"}]. Trains on the temporal past, tests on the
    future, and returns a metrics dict. Classes unseen in training are reported
    separately (a real, honest failure mode of temporal evaluation)."""
    from sklearn.metrics import accuracy_score, f1_score

    from .classify.sklearn_model import SklearnCweClassifier

    train, test = temporal_split(rows, train_frac)
    if not train or not test:
        return {"error": "not enough data for a temporal split",
                "n_train": len(train), "n_test": len(test)}

    clf = SklearnCweClassifier.train([r["text"] for r in train],
                                     [r["cwe"] for r in train])
    seen = set(clf._labels)

    y_true, y_pred, confs = [], [], []
    unseen = 0
    for r in test:
        if r["cwe"] not in seen:
            unseen += 1
        preds = clf.predict(r["text"], top_k=1)
        y_true.append(r["cwe"])
        if preds:
            y_pred.append(preds[0].cwe_id)
            confs.append(preds[0].confidence)
        else:
            y_pred.append("<none>")
            confs.append(0.0)

    # most-confused pairs
    confused = Counter()
    for t, p in zip(y_true, y_pred):
        if t != p:
            confused[(t, p)] += 1

    # gate effect: accuracy on the auto-accepted subset
    gated = [(t, p) for t, p, c in zip(y_true, y_pred, confs) if c >= gate]
    gate_acc = (sum(1 for t, p in gated if t == p) / len(gated)) if gated else None

    return {
        "n_train": len(train),
        "n_test": len(test),
        "n_classes_train": len(seen),
        "n_test_unseen_in_train": unseen,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "macro_f1": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "weighted_f1": round(f1_score(y_true, y_pred, average="weighted", zero_division=0), 4),
        "gate": gate,
        "gate_auto_accept_frac": round(len(gated) / len(test), 4),
        "gate_accuracy_on_accepted": None if gate_acc is None else round(gate_acc, 4),
        "top_confusions": [{"true": t, "pred": p, "n": n}
                           for (t, p), n in confused.most_common(8)],
        "note": ("Temporal split (train on past, test on future). macro_f1 is the "
                 "honest headline — accuracy flatters frequent classes. Compare "
                 "against a random split to see the inflation the design warns about."),
    }
