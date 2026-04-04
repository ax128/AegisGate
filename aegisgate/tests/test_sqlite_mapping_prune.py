from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from aegisgate.storage.sqlite_store import SqliteKVStore


def test_prune_expired_mappings_removes_old_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "aegisgate.db"
    store = SqliteKVStore(db_path=str(db_path))
    store.set_mapping("S1", "R1", {"{{X}}": "secret"})

    old_ts = int(time.time()) - 1000
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "UPDATE mapping_store SET created_at = ? WHERE session_id = ? AND request_id = ?",
            (old_ts, "S1", "R1"),
        )
        conn.commit()
    finally:
        conn.close()

    removed = store.prune_expired_mappings(max_age_seconds=300)
    assert removed >= 1

    fresh = SqliteKVStore(db_path=str(db_path))
    assert fresh.get_mapping("S1", "R1") == {}


def test_prune_expired_mappings_preserves_recent_rows(tmp_path: Path) -> None:
    """C-03: freshly inserted rows must NOT be pruned by prune_expired_mappings.

    The minimum safety window enforced by prune_expired_mappings is 300 s,
    so rows with created_at = now() survive regardless of the max_age argument.
    """
    db_path = tmp_path / "aegisgate.db"
    store = SqliteKVStore(db_path=str(db_path))
    store.set_mapping("S2", "R2", {"{{Y}}": "fresh-secret"})

    # The store sets created_at = now(); prune with a tiny max_age
    # to ensure the 300-s safety floor protects the new row.
    removed = store.prune_expired_mappings(max_age_seconds=1)
    assert removed == 0, "freshly inserted row must not be pruned"

    fresh = SqliteKVStore(db_path=str(db_path))
    assert fresh.get_mapping("S2", "R2") == {"{{Y}}": "fresh-secret"}

