"""SQLite-backed persistence for sender history and allow/block lists, so
FIRST_TIME_SENDER and WHITELISTED_SENDER/BLACKLISTED_SENDER rules work across runs."""
from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS senders (
    address TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS list_entries (
    entry TEXT NOT NULL,
    list_type TEXT NOT NULL CHECK (list_type IN ('allow', 'block')),
    PRIMARY KEY (entry, list_type)
);

CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id TEXT NOT NULL,
    from_addr TEXT,
    subject TEXT,
    score REAL NOT NULL,
    is_spam INTEGER NOT NULL,
    action TEXT NOT NULL,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def known_senders(self) -> set[str]:
        with closing(self._conn()) as conn:
            rows = conn.execute("SELECT address FROM senders").fetchall()
        return {r[0] for r in rows}

    def record_sender(self, address: str) -> None:
        if not address:
            return
        address = address.lower()
        with closing(self._conn()) as conn:
            conn.execute(
                """
                INSERT INTO senders (address, first_seen, last_seen, message_count)
                VALUES (?, datetime('now'), datetime('now'), 1)
                ON CONFLICT(address) DO UPDATE SET
                    last_seen = datetime('now'),
                    message_count = message_count + 1
                """,
                (address,),
            )
            conn.commit()

    def allowlist(self) -> set[str]:
        return self._list_entries("allow")

    def blocklist(self) -> set[str]:
        return self._list_entries("block")

    def _list_entries(self, list_type: str) -> set[str]:
        with closing(self._conn()) as conn:
            rows = conn.execute(
                "SELECT entry FROM list_entries WHERE list_type = ?", (list_type,)
            ).fetchall()
        return {r[0].lower() for r in rows}

    def add_to_list(self, entry: str, list_type: str) -> None:
        with closing(self._conn()) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO list_entries (entry, list_type) VALUES (?, ?)",
                (entry.lower(), list_type),
            )
            conn.commit()

    def remove_from_list(self, entry: str, list_type: str) -> None:
        with closing(self._conn()) as conn:
            conn.execute(
                "DELETE FROM list_entries WHERE entry = ? AND list_type = ?",
                (entry.lower(), list_type),
            )
            conn.commit()

    def log_scan(self, provider_id: str, from_addr: str, subject: str, score: float, is_spam: bool, action: str) -> None:
        with closing(self._conn()) as conn:
            conn.execute(
                """INSERT INTO scan_log (provider_id, from_addr, subject, score, is_spam, action)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (provider_id, from_addr, subject, score, int(is_spam), action),
            )
            conn.commit()

    def stats(self) -> dict:
        with closing(self._conn()) as conn:
            total, spam = conn.execute(
                "SELECT COUNT(*), SUM(is_spam) FROM scan_log"
            ).fetchone()
        return {"total_scanned": total or 0, "spam_flagged": spam or 0}
