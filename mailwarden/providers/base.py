from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from ..message import ParsedMessage


class MailProvider(ABC):
    """Common interface every backend (Gmail API, IMAP, ...) implements, so
    the scanner and rule engine never need to know which one they're talking to."""

    def __init__(self, account_config):
        self.config = account_config

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def fetch_inbox_messages(self, limit: int | None = None) -> Iterator[ParsedMessage]:
        """Yields unprocessed inbox messages as ParsedMessage objects."""
        ...

    @abstractmethod
    def mark_as_spam(self, msg: ParsedMessage, dry_run: bool) -> str:
        """Applies the spam verdict per the account's configured `action`.
        Returns a short string describing what was done (or would be done)."""
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
