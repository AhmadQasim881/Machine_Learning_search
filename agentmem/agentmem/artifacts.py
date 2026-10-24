"""
agentmem.artifacts — immutable, content-addressed artifact store.

Raw evidence (source excerpts, SARIF, build/sanitizer logs, crash dumps,
testcases, reports) must never be truncated or normalized away — the only copy
is preserved verbatim here and referenced by SHA-256 digest. A separate bounded,
sanitized, secret-redacted *projection* (see `agentmem.security.project_text`) is
what goes into prompts and search.

Writes are atomic: bytes are written to a temp file, fsynced, then `os.replace`d
into their final digest path. An interrupted write therefore cannot leave a
readable partial artifact at the canonical path (the temp file carries a random
name and is cleaned up). Reads re-verify the digest, so silent corruption is
detected rather than returned as evidence.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from typing import Optional


class ArtifactStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(self.root, exist_ok=True)

    def _path_for(self, digest: str) -> str:
        # shard by digest prefix to keep directories small
        return os.path.join(self.root, digest[:2], digest[2:4], digest)

    @staticmethod
    def digest_of(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def put_bytes(self, data: bytes) -> dict:
        """Store `data` immutably; return {sha256, size, storage_path}. Idempotent:
        the same bytes dedupe to the same path. Atomic via temp-write + rename."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("artifact data must be bytes")
        data = bytes(data)
        digest = self.digest_of(data)
        dst = self._path_for(digest)
        rel = os.path.relpath(dst, self.root)
        if os.path.exists(dst):                       # already stored -> dedupe
            return {"sha256": digest, "size": len(data), "storage_path": rel}
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dst), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, dst)                      # atomic publish
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return {"sha256": digest, "size": len(data), "storage_path": rel}

    def put_text(self, text: str) -> dict:
        return self.put_bytes((text or "").encode("utf-8"))

    def get_bytes(self, digest: str, verify: bool = True) -> Optional[bytes]:
        """Return the stored bytes for `digest`, or None if absent. With
        `verify=True` (default) the content is re-hashed and a mismatch raises
        (corruption is never returned as if it were sound evidence)."""
        dst = self._path_for(digest)
        if not os.path.exists(dst):
            return None
        with open(dst, "rb") as fh:
            data = fh.read()
        if verify and self.digest_of(data) != digest:
            raise ValueError(f"artifact {digest} is corrupt (digest mismatch)")
        return data

    def verify(self, digest: str) -> bool:
        """True iff the artifact exists and its bytes still hash to `digest`."""
        try:
            return self.get_bytes(digest, verify=True) is not None
        except ValueError:
            return False

    def exists(self, digest: str) -> bool:
        return os.path.exists(self._path_for(digest))
