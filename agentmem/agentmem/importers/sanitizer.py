"""
agentmem.importers.sanitizer — parse an AddressSanitizer / UBSan crash log into a
structured diagnostic and record it as immutable evidence + a validation run.

The raw log is preserved verbatim as a content-addressed artifact; a bounded,
structured projection (error type, access, top frames) goes into the evidence row.
A parsed crash is an OBSERVATION under recorded conditions — it does NOT set a
finding's severity or prove exploitable memory corruption. If the log cannot be
classified, the type is 'unclassified' and the raw log is still preserved.
"""
from __future__ import annotations

import re
from typing import Optional

_ASAN_TYPE = re.compile(r"ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_\-]+)")
_SUMMARY = re.compile(r"SUMMARY:\s*(?:Address|UndefinedBehavior)Sanitizer:\s*([A-Za-z0-9_\-]+)")
_UBSAN = re.compile(r"runtime error:\s*(.+)")
_ACCESS = re.compile(r"\b(READ|WRITE) of size (\d+)")
_FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s*$")


def parse_sanitizer_log(raw_log: str, max_frames: int = 12) -> dict:
    """Parse ASan/UBSan text into {type, access, access_size, top_frames}. Pure
    function; no storage. `type` is 'unclassified' if nothing matches."""
    text = raw_log or ""
    m = _ASAN_TYPE.search(text) or _SUMMARY.search(text)
    diag_type = m.group(1) if m else None
    if diag_type is None:
        ub = _UBSAN.search(text)
        diag_type = ("undefined-behavior" if ub else "unclassified")
    access = _ACCESS.search(text)
    frames = [f.group(2) for f in (_FRAME.match(ln) for ln in text.splitlines()) if f]
    return {"type": diag_type,
            "access": access.group(1) if access else None,
            "access_size": int(access.group(2)) if access else None,
            "top_frames": frames[:max_frames]}


def import_sanitizer_log(mem, snapshot_id: int, raw_log: str, hypothesis_id: Optional[int] = None,
                         validation_status: str = "failed", trust: str = "tool_verified",
                         build_manifest_digest: str = "") -> dict:
    """Record a sanitizer crash log: raw artifact + a 'crash' evidence row + a
    validation run (kind='repro'). Returns the structured diagnostic plus the ids.
    Does not create a finding or assign severity — that is a separate human/analysis
    judgement."""
    mem._require_snapshot(snapshot_id)
    diag = parse_sanitizer_log(raw_log)
    prov = mem.add_provenance(snapshot_id, tool="sanitizer", actor="sanitizer",
                              actor_kind="tool", trust=trust)
    top = diag["top_frames"][0] if diag["top_frames"] else "?"
    acc = f" {diag['access']} size {diag['access_size']}" if diag["access"] else ""
    projection = f"[{diag['type']}]{acc} at {top}"
    ev = mem.add_evidence(snapshot_id, "crash", raw=raw_log, projection=projection,
                          status="observed", trust=trust, provenance_id=prov,
                          media_type="text/plain")
    vr = mem.add_validation_run(snapshot_id, kind="repro", status=validation_status,
                                hypothesis_id=hypothesis_id, logs=raw_log,
                                build_manifest_digest=build_manifest_digest, provenance_id=prov)
    art = mem.get_evidence(ev)["artifact_id"]
    sha = mem.store.artifact_row(art)["sha256"] if art else None
    return {"diagnostic": diag, "evidence_id": ev, "validation_run_id": vr,
            "artifact_sha256": sha}
