"""Generic IMAP backend (Outlook/Office365, Yahoo, iCloud, self-hosted, ...)
using the stdlib imaplib. Most providers require an app password rather than
your normal account password when 2FA is enabled -- set that via
`password_env` in the account config, not a literal password in the file.
"""
from __future__ import annotations

import imaplib
from typing import Iterator, Optional

from ..message import ParsedMessage
from .base import MailProvider


class ImapProvider(MailProvider):
    def __init__(self, account_config):
        super().__init__(account_config)
        self._conn: Optional[imaplib.IMAP4_SSL] = None
        self._capabilities: set[bytes] = set()

    def connect(self) -> None:
        host = self.config.get("host")
        port = self.config.get("port", 993)
        username = self.config.get("username")
        password = self.config.password()
        mailbox = self.config.get("mailbox", "INBOX")

        if not host or not username or not password:
            raise ValueError(
                f"IMAP account {self.config.name!r} needs host, username, and "
                "password (or password_env) set in its config."
            )

        self._conn = imaplib.IMAP4_SSL(host, port)
        self._conn.login(username, password)
        typ, caps = self._conn.capability()
        if typ == "OK":
            self._capabilities = {c.upper() for c in caps[0].split()}
        self._conn.select(mailbox)

    def fetch_inbox_messages(self, limit: Optional[int] = None) -> Iterator[ParsedMessage]:
        search_criteria = self.config.get("search", "UNSEEN")
        typ, data = self._conn.uid("search", None, search_criteria)
        if typ != "OK":
            return
        uids = data[0].split()
        if limit:
            uids = uids[:limit]

        for raw_uid in uids:
            typ, msg_data = self._conn.uid("fetch", raw_uid, "(RFC822)")
            if typ != "OK" or not msg_data or msg_data[0] is None:
                continue
            raw_bytes = msg_data[0][1]
            uid_str = raw_uid.decode() if isinstance(raw_uid, bytes) else str(raw_uid)
            yield ParsedMessage.from_bytes(raw_bytes, provider_id=uid_str, folder=self.config.get("mailbox", "INBOX"))

    def _ensure_folder(self, folder: str) -> None:
        typ, data = self._conn.list()
        existing = " ".join(d.decode(errors="replace") for d in (data or []) if d)
        if f'"{folder}"' in existing or folder in existing:
            return
        self._conn.create(folder)

    def _move(self, uid: str, dest_folder: str) -> None:
        self._ensure_folder(dest_folder)
        if b"MOVE" in self._capabilities:
            self._conn.uid("MOVE", uid, dest_folder)
        else:
            self._conn.uid("COPY", uid, dest_folder)
            self._conn.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            self._conn.expunge()

    def mark_as_spam(self, msg: ParsedMessage, dry_run: bool) -> str:
        action = self.config.action
        spam_folder = self.config.get("spam_folder", "Junk")
        trash_folder = self.config.get("trash_folder", "Trash")

        if action in ("label", "move"):
            if dry_run:
                return f"[dry-run] would move UID {msg.provider_id} to {spam_folder!r}"
            self._move(msg.provider_id, spam_folder)
            return f"moved UID {msg.provider_id} to {spam_folder!r}"

        if action == "trash":
            if dry_run:
                return f"[dry-run] would move UID {msg.provider_id} to {trash_folder!r}"
            self._move(msg.provider_id, trash_folder)
            return f"moved UID {msg.provider_id} to {trash_folder!r}"

        if action == "delete":
            if not self.config.get("allow_permanent_delete", False):
                if dry_run:
                    return f"[dry-run] would move UID {msg.provider_id} to {spam_folder!r} (permanent delete not enabled)"
                self._move(msg.provider_id, spam_folder)
                return f"moved UID {msg.provider_id} to {spam_folder!r} (permanent delete not enabled)"
            if dry_run:
                return f"[dry-run] would PERMANENTLY delete UID {msg.provider_id}"
            self._conn.uid("STORE", msg.provider_id, "+FLAGS", "(\\Deleted)")
            self._conn.expunge()
            return f"permanently deleted UID {msg.provider_id}"

        raise ValueError(f"Unknown action {action!r}")

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except imaplib.IMAP4.error:
                pass
            self._conn.logout()
            self._conn = None
