"""CWE classification: the swappable interface, the gate, and the baseline stub."""
from .base import DEFAULT_GATE, CweClassifier, apply_gate  # noqa: F401
from .keyword_stub import KeywordCweClassifier  # noqa: F401


def default_classifier() -> CweClassifier:
    """The classifier the CLI uses unless told otherwise. Swap this one line
    (or pass --classifier) when you plug in a real model."""
    return KeywordCweClassifier()
