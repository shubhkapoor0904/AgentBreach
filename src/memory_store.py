"""
Persistent memory store module backing agent long-term memory using SQLite.
Demonstrates state persistence across LLM context window resets.
"""

import json
import sqlite3
import os
from typing import Dict, Any, List, Optional


class PersistentMemoryStore:
    def __init__(self, db_path: str = "agent_memory.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_entries (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT DEFAULT 'general',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            conn.commit()

    def write(self, key: str, value: str, category: str = "general", metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        meta_json = json.dumps(metadata or {})
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO memory_entries (key, value, category, metadata)
                VALUES (?, ?, ?, ?)
                """,
                (key, value, category, meta_json)
            )
            conn.commit()
        return {"key": key, "value": value, "category": category, "metadata": metadata or {}}

    def read(self, key: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value, category, metadata FROM memory_entries WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return {
                    "key": row[0],
                    "value": row[1],
                    "category": row[2],
                    "metadata": json.loads(row[3]) if row[3] else {}
                }
        return None

    def search(self, query: str) -> List[Dict[str, Any]]:
        results = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key, value, category, metadata FROM memory_entries WHERE value LIKE ? OR key LIKE ?",
                (f"%{query}%", f"%{query}%")
            )
            for row in cursor.fetchall():
                results.append({
                    "key": row[0],
                    "value": row[1],
                    "category": row[2],
                    "metadata": json.loads(row[3]) if row[3] else {}
                })
        return results

    def get_all(self) -> List[Dict[str, Any]]:
        results = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value, category, metadata FROM memory_entries")
            for row in cursor.fetchall():
                results.append({
                    "key": row[0],
                    "value": row[1],
                    "category": row[2],
                    "metadata": json.loads(row[3]) if row[3] else {}
                })
        return results

    def clear(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM memory_entries")
            conn.commit()

    def close(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
