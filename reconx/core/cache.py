"""Persistent SQLite-backed cache with TTL support for ReconX."""
from __future__ import annotations
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "reconx"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "cache.sqlite"

class Cache:
    """Thread-safe SQLite-backed key-value cache with expiration."""

    def __init__(self, db_path: str | Path | None = None, enabled: bool = True):
        self.enabled = enabled
        if not self.enabled:
            self.db_path = None
            return

        if db_path is None:
            cache_env = os.getenv("RECONX_CACHE_PATH")
            if cache_env:
                self.db_path = Path(cache_env)
            else:
                try:
                    DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    self.db_path = DEFAULT_CACHE_FILE
                except Exception:
                    self.db_path = Path("./recon_cache.sqlite")
        else:
            self.db_path = Path(db_path)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        if not self.enabled or not self.db_path:
            return
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        namespace TEXT NOT NULL,
                        key TEXT NOT NULL,
                        value TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        created_at REAL NOT NULL,
                        PRIMARY KEY (namespace, key)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries (expires_at)")
                conn.commit()
        except Exception:
            self.enabled = False

    def get(self, namespace: str, key: str) -> Any | None:
        if not self.enabled or not self.db_path:
            return None
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value, expires_at FROM cache_entries WHERE namespace = ? AND key = ?",
                    (namespace, key),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                val_str, expires_at = row
                if expires_at < now:
                    cursor.execute("DELETE FROM cache_entries WHERE namespace = ? AND key = ?", (namespace, key))
                    conn.commit()
                    return None
                return json.loads(val_str)
        except Exception:
            return None

    def set(self, namespace: str, key: str, value: Any, ttl: float = 86400.0) -> None:
        if not self.enabled or not self.db_path:
            return
        now = time.time()
        expires_at = now + max(0.0, ttl)
        try:
            val_str = json.dumps(value)
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO cache_entries (namespace, key, value, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(namespace, key) DO UPDATE SET
                        value = excluded.value,
                        expires_at = excluded.expires_at,
                        created_at = excluded.created_at
                    """,
                    (namespace, key, val_str, expires_at, now),
                )
                conn.commit()
        except Exception:
            pass

    def delete(self, namespace: str, key: str) -> None:
        if not self.enabled or not self.db_path:
            return
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM cache_entries WHERE namespace = ? AND key = ?", (namespace, key))
                conn.commit()
        except Exception:
            pass

    def purge_expired(self) -> int:
        if not self.enabled or not self.db_path:
            return 0
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache_entries WHERE expires_at < ?", (now,))
                deleted = cursor.rowcount
                conn.commit()
                return deleted
        except Exception:
            return 0

    def clear(self) -> None:
        if not self.enabled or not self.db_path:
            return
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM cache_entries")
                conn.commit()
        except Exception:
            pass

_DEFAULT_CACHE: Cache | None = None

def get_cache(enabled: bool = True) -> Cache:
    global _DEFAULT_CACHE
    if _DEFAULT_CACHE is None:
        _DEFAULT_CACHE = Cache(enabled=enabled)
    return _DEFAULT_CACHE
