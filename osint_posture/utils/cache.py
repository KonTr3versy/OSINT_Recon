from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional


class CacheBase:
    def get(self, key: str) -> Optional[dict]:
        raise NotImplementedError

    def set(self, key: str, value: dict) -> None:
        raise NotImplementedError


class SqliteCache(CacheBase):
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, ts REAL)"
            )
            conn.commit()

    def get(self, key: str) -> Optional[dict]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM cache WHERE key=?", (key,)).fetchone()
            if not row:
                return None
            return json.loads(row[0])

    def set(self, key: str, value: dict) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time()),
            )
            conn.commit()


class FileCache(CacheBase):
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).mkdir(parents=True, exist_ok=True)

    def _file_path(self, key: str) -> str:
        safe = key.replace("/", "_")
        return os.path.join(self.path, f"{safe}.json")

    def get(self, key: str) -> Optional[dict]:
        fp = self._file_path(key)
        if not os.path.exists(fp):
            return None
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)

    def set(self, key: str, value: dict) -> None:
        fp = self._file_path(key)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2)


def build_cache(cache_mode: str, base_path: str) -> Optional[CacheBase]:
    if cache_mode == "sqlite":
        return SqliteCache(os.path.join(base_path, "cache.db"))
    if cache_mode == "files":
        return FileCache(os.path.join(base_path, "cache"))
    return None
