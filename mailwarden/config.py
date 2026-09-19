from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AccountConfig:
    name: str
    provider: str  # "gmail" | "imap"
    action: str = "label"  # "label" | "move" | "trash" | "delete"
    dry_run: bool = True
    raw: dict = field(default_factory=dict)

    def get(self, key: str, default=None):
        return self.raw.get(key, default)

    def password(self) -> str | None:
        """IMAP password, resolved from an env var reference so it never
        needs to sit in the config file in plaintext."""
        if "password" in self.raw:
            return self.raw["password"]
        env_name = self.raw.get("password_env")
        if env_name:
            return os.environ.get(env_name)
        return None


@dataclass
class AppConfig:
    accounts: list[AccountConfig]
    rules_file: str | None = None
    dnsbl_enabled: bool = True
    dnsbl_zone: str = "zen.spamhaus.org"
    store_path: str = "mailwarden.db"
    config_dir: Path = field(default_factory=Path.cwd)

    @classmethod
    def load(cls, path: Path | str) -> "AppConfig":
        path = Path(path)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        accounts = []
        for acc in data.get("accounts", []):
            accounts.append(AccountConfig(
                name=acc["name"],
                provider=acc["provider"],
                action=acc.get("action", "label"),
                dry_run=acc.get("dry_run", True),
                raw=acc,
            ))

        return cls(
            accounts=accounts,
            rules_file=data.get("rules_file"),
            dnsbl_enabled=data.get("dnsbl_enabled", True),
            dnsbl_zone=data.get("dnsbl_zone", "zen.spamhaus.org"),
            store_path=data.get("store_path", "mailwarden.db"),
            config_dir=path.parent.resolve(),
        )

    def resolve(self, relative: str) -> Path:
        """Resolves a path from the config file relative to the config file's
        own directory, so configs are portable regardless of cwd."""
        p = Path(relative)
        return p if p.is_absolute() else self.config_dir / p
