"""
agentmem.embeddings — optional semantic vectors (spec §3.2).

An `EmbeddingProvider` turns node text into a fixed-dim unit vector for fuzzy
recall. The default `HashingProvider` is DEPENDENCY-FREE (hashed word + char
n-gram features) so semantic recall works with zero installs; swap in a real
model (sentence-transformers / an API) behind the same interface for quality.

With no provider configured, semantic retrieval is simply skipped and the exact +
graph retrievers carry the load — nothing breaks.
"""
from __future__ import annotations

import array
import hashlib
import math
from typing import Optional

from . import config

_SALIENT = ("vuln_class", "name", "kind", "host", "path", "param", "var",
            "symbol", "file", "goal", "oracle", "missing_capability")


class EmbeddingProvider:
    dim = config.EMBED_DIM

    def encode(self, text: str) -> Optional[list[float]]:   # pragma: no cover
        raise NotImplementedError


class NoneProvider(EmbeddingProvider):
    def encode(self, text: str) -> Optional[list[float]]:
        return None


class HashingProvider(EmbeddingProvider):
    """Hashed word + char-trigram features -> L2-normalized vector. Deterministic,
    stdlib-only. Good enough for fuzzy 'is this like that' recall; not a semantic
    model. Signed hashing reduces collision bias."""

    def __init__(self, dim: int = config.EMBED_DIM, ngram: int = 3):
        self.dim = dim
        self.ngram = ngram

    def encode(self, text: str) -> Optional[list[float]]:
        if not text:
            return None
        toks = text.lower().split()
        feats = list(toks)
        for w in toks:
            for i in range(len(w) - self.ngram + 1):
                feats.append(w[i:i + self.ngram])
        if not feats:
            return None
        vec = [0.0] * self.dim
        for f in feats:
            h = int(hashlib.md5(f.encode("utf-8")).hexdigest(), 16)   # noqa: S324 (not security)
            vec[h % self.dim] += 1.0 if (h >> 8) & 1 else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


def text_for(attrs: dict, node_type: str) -> str:
    """Build the text to embed for a node from its salient attributes."""
    parts = [node_type]
    for k in _SALIENT:
        v = attrs.get(k)
        if isinstance(v, str) and v:
            parts.append(v)
    return " ".join(parts)


def cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def to_blob(vec: list[float]) -> bytes:
    return array.array("f", vec).tobytes()


def from_blob(blob: bytes) -> list[float]:
    a = array.array("f")
    a.frombytes(blob)
    return list(a)
