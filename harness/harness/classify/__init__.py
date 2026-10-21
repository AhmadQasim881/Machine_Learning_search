"""CWE classification: the swappable interface, the gate, and the baseline stub."""
from .base import DEFAULT_GATE, CweClassifier, apply_gate  # noqa: F401
from .keyword_stub import KeywordCweClassifier  # noqa: F401


def default_classifier() -> CweClassifier:
    """The zero-dependency baseline. Used when no trained model is supplied."""
    return KeywordCweClassifier()


def load_classifier(model_path: str | None = None) -> CweClassifier:
    """Pick a classifier: a trained sklearn model if a path is given, else the
    keyword baseline. Keeps the CLI/pipeline model-agnostic."""
    if model_path:
        from .sklearn_model import SklearnCweClassifier
        return SklearnCweClassifier.load(model_path)
    return default_classifier()
