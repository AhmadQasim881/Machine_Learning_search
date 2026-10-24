"""
agentmem.security — memory-poisoning defenses (spec §6).

A bug-bounty target is adversarial and its responses become memory input, so
target-derived text is the primary poisoning vector. This module enforces:
  - trust levels (tool_verified > agent_asserted > llm_inferred > target_derived)
  - sanitize(): strip control chars + prompt-injection markers from target text
  - the verification gate (confirmed only via a concrete oracle)
  - a SecretsVault so credentials live by handle, never in graph/prompt/summary
  - redaction of secret values from any text that may reach an LLM

NOTE on the vault cipher: this uses a stdlib-only keyed keystream (sha256-CTR).
It is obfuscation-at-rest to keep secrets out of plaintext graph/logs — NOT a
substitute for a real KMS/HSM. For production, back `SecretsVault` with Fernet
(cryptography) or a cloud KMS; the interface stays the same.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets as _secrets
import unicodedata
from typing import Optional

from . import config

# C0 + C1 control chars (keep none of them); zero-width + bidi override chars
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁯﻿]")
_WS = re.compile(r"\s+")


def trust_rank(trust: str) -> int:
    return config.TRUST_RANK.get(trust, 0)


def may_seed_chain(trust: str) -> bool:
    return trust_rank(trust) >= config.TRUST_RANK[config.CHAIN_SEED_MIN_TRUST]


def sanitize(text: str, max_len: int = 20000) -> str:
    """Make target-derived text safe to STORE and to place in an LLM prompt.
    Strips control characters and neutralizes known prompt-injection markers.
    The text remains data — it can never mint a capability token (only typed
    extractors + an oracle do that)."""
    if not text:
        return ""
    # fold compatibility/homoglyph forms, drop invisible + control chars, then
    # collapse whitespace runs so multi-space / newline-split markers are caught.
    t = unicodedata.normalize("NFKC", text)
    t = _INVISIBLE.sub("", t)
    t = _CTRL.sub(" ", t)
    t = _WS.sub(" ", t)[:max_len]
    low = t.lower()
    for marker in config.INJECTION_MARKERS:
        idx = low.find(marker)
        while idx != -1:
            t = t[:idx] + "[redacted-injection]" + t[idx + len(marker):]
            low = t.lower()
            idx = low.find(marker)
    return t


def project_text(raw: str, vault: Optional["SecretsVault"] = None,
                 max_chars: int = 4000) -> tuple[str, bool]:
    """Build a bounded, sanitized, secret-redacted text PROJECTION of `raw` for
    prompts and search. This never replaces the raw evidence (which is preserved
    verbatim as a content-addressed artifact) — it is a lossy, safe-to-show view.

    Order matters: sanitize (fold unicode, strip control/zero-width/bidi, defang
    injection markers) and redact secrets BEFORE truncating, so the bound cannot
    slice a secret or a control sequence in half. Returns (projection, truncated).
    """
    if not raw:
        return "", False
    t = sanitize(raw, max_len=max(max_chars * 4, len(raw)))  # sanitize full text first
    if vault is not None:
        t = vault.redact(t)
    truncated = len(t) > max_chars
    if truncated:
        marker = f" …[+{len(t) - max_chars} chars in artifact]"
        t = t[:max_chars] + marker
    return t, truncated


class SecretsVault:
    """Stores secret values encrypted (sha256-CTR keystream) and hands back a
    stable handle. The graph/prompts/summaries reference the handle only."""

    def __init__(self, store, key: Optional[bytes] = None):
        self.store = store
        env = os.environ.get("AGENTMEM_VAULT_KEY")
        existing = store._meta("vault_key")
        if key is not None:
            self._key = key
        elif env:
            # external key (preferred for anything real): derived, never persisted
            self._key = hashlib.sha256(env.encode("utf-8")).digest()
        elif existing:
            self._key = base64.b64decode(existing)
        else:
            # DEV fallback: a random key stored beside the ciphertext (NOT secure
            # against local disk access — set AGENTMEM_VAULT_KEY or use a KMS).
            self._key = os.urandom(32)
            store._set_meta("vault_key", base64.b64encode(self._key).decode())
            store.conn.commit()

    def _keystream(self, n: int, nonce: bytes) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < n:
            out.extend(hashlib.sha256(self._key + nonce + counter.to_bytes(8, "big")).digest())
            counter += 1
        return bytes(out[:n])

    def put(self, value: str, kind: str = "token", subject: str = "",
            acquired_obs: Optional[int] = None) -> str:
        nonce = os.urandom(16)
        data = value.encode("utf-8")
        enc = nonce + bytes(a ^ b for a, b in zip(data, self._keystream(len(data), nonce)))
        handle = "secret:" + _secrets.token_hex(8)
        self.store.conn.execute(
            "INSERT INTO secrets(handle,kind,value_enc,subject,acquired_obs,valid) VALUES(?,?,?,?,?,1)",
            (handle, kind, enc, subject, acquired_obs))
        self.store.conn.commit()
        return handle

    def get(self, handle: str) -> Optional[str]:
        r = self.store.conn.execute(
            "SELECT value_enc FROM secrets WHERE handle=? AND valid=1", (handle,)).fetchone()
        if not r:
            return None
        blob = r["value_enc"]
        nonce, enc = blob[:16], blob[16:]
        return bytes(a ^ b for a, b in zip(enc, self._keystream(len(enc), nonce))).decode("utf-8", "replace")

    def redact(self, text: str) -> str:
        """Replace any stored secret value appearing in `text` with its handle."""
        if not text:
            return text
        for r in self.store.conn.execute("SELECT handle FROM secrets WHERE valid=1").fetchall():
            val = self.get(r["handle"])
            if val and len(val) >= 6 and val in text:
                text = text.replace(val, f"<{r['handle']}>")
        return text
