"""
agentmem.backup — backup / restore / verify for the metadata database AND the
content-addressed artifact store.

A backup is a directory containing:
  * metadata.db        — a consistent copy of the SQLite database (via the online
                         backup API, safe to run on an open WAL database)
  * artifacts/         — a copy of the content-addressed artifact tree
  * manifest.json      — counts, schema version, and a created timestamp

`verify` reopens a database and confirms every artifact row still resolves to its
bytes by SHA-256, so a restore can be trusted before research resumes.

CLI:
    python -m agentmem.backup backup  <db_path> <dest_dir>
    python -m agentmem.backup restore <dest_dir> <db_path>
    python -m agentmem.backup verify  <db_path>
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import time

from .store import Store, _artifact_root


def backup(db_path: str, dest_dir: str) -> dict:
    """Copy the database (consistently) and its artifact store into dest_dir."""
    os.makedirs(dest_dir, exist_ok=True)
    src = sqlite3.connect(db_path)
    try:
        dst = sqlite3.connect(os.path.join(dest_dir, "metadata.db"))
        try:
            src.backup(dst)                          # online, consistent snapshot
        finally:
            dst.close()
    finally:
        src.close()
    art_src = _artifact_root(db_path)
    art_dst = os.path.join(dest_dir, "artifacts")
    n_art = 0
    if os.path.isdir(art_src):
        if os.path.exists(art_dst):
            shutil.rmtree(art_dst)
        shutil.copytree(art_src, art_dst)
        n_art = sum(len(files) for _, _, files in os.walk(art_dst))
    manifest = {"created_ts": time.time(), "artifact_files": n_art,
                "source_db": os.path.abspath(db_path)}
    with open(os.path.join(dest_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def restore(dest_dir: str, db_path: str) -> dict:
    """Restore a backup directory to db_path (+ its artifact store)."""
    meta = os.path.join(dest_dir, "metadata.db")
    if not os.path.exists(meta):
        raise FileNotFoundError(f"no metadata.db in backup {dest_dir}")
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    # clear stale WAL/SHM siblings so the restored DB is authoritative
    for suffix in ("", "-wal", "-shm"):
        p = db_path + suffix
        if os.path.exists(p):
            os.remove(p)
    shutil.copyfile(meta, db_path)
    art_src = os.path.join(dest_dir, "artifacts")
    art_dst = _artifact_root(db_path)
    if os.path.isdir(art_src):
        if os.path.exists(art_dst):
            shutil.rmtree(art_dst)
        shutil.copytree(art_src, art_dst)
    return verify(db_path)


def verify(db_path: str) -> dict:
    """Reopen the database and confirm every artifact row resolves by digest."""
    s = Store(db_path)
    try:
        rows = s.conn.execute("SELECT id, sha256 FROM artifacts").fetchall()
        bad = [r["sha256"] for r in rows if not s.artifacts.verify(r["sha256"])]
        return {"artifacts": len(rows), "resolved": len(rows) - len(bad),
                "missing_or_corrupt": bad, "ok": not bad}
    finally:
        s.close()


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "backup" and len(argv) == 3:
        print(json.dumps(backup(argv[1], argv[2]), indent=2))
    elif cmd == "restore" and len(argv) == 3:
        print(json.dumps(restore(argv[1], argv[2]), indent=2))
    elif cmd == "verify" and len(argv) == 2:
        res = verify(argv[1])
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
