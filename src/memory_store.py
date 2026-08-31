import json
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime


class SQLiteMemoryStore:
    """Persistent SQLite store for agent long-term key-value memory and message history."""

    def __init__(self, db_path: str = "agent_memory.db"):
        self.db_path = db_path
        self._setup()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _setup(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'general',
                    updated_at TEXT NOT NULL,
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS message_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()

    def put(self, key: str, value: str, category: str = "general", metadata: Optional[Dict[str, Any]] = None) -> None:
        now = datetime.utcnow().isoformat()
        meta_str = json.dumps(metadata) if metadata else None
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO memory_kv (key, value, category, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    category=excluded.category,
                    updated_at=excluded.updated_at,
                    metadata=excluded.metadata
                """,
                (key, value, category, now, meta_str)
            )
            conn.commit()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT key, value, category, updated_at, metadata FROM memory_kv WHERE key = ?", (key,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                "key": row["key"],
                "value": row["value"],
                "category": row["category"],
                "updated_at": row["updated_at"],
                "metadata": json.loads(row["metadata"]) if row["metadata"] else {}
            }

    def list_all(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT key, value, category, updated_at, metadata FROM memory_kv ORDER BY updated_at ASC")
            return [
                {
                    "key": row["key"],
                    "value": row["value"],
                    "category": row["category"],
                    "updated_at": row["updated_at"],
                    "metadata": json.loads(row["metadata"]) if row["metadata"] else {}
                }
                for row in cur.fetchall()
            ]

    def delete(self, key: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM memory_kv WHERE key = ?", (key,))
            conn.commit()
            return cur.rowcount > 0

    def append_message(self, role: str, content: str) -> None:
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO message_history (role, content, timestamp) VALUES (?, ?, ?)",
                (role, content, now)
            )
            conn.commit()

    def clear_messages(self) -> None:
        """Clears short-term conversation context history without affecting persistent memory_kv."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM message_history")
            conn.commit()

    def purge_all(self) -> None:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM memory_kv")
            conn.execute("DELETE FROM message_history")
            conn.commit()
