from .base import MailProvider
from .gmail_provider import GmailProvider
from .imap_provider import ImapProvider

PROVIDERS = {
    "gmail": GmailProvider,
    "imap": ImapProvider,
}


def build_provider(account_config) -> MailProvider:
    try:
        cls = PROVIDERS[account_config.provider]
    except KeyError:
        raise ValueError(f"Unknown provider {account_config.provider!r}; expected one of {list(PROVIDERS)}")
    return cls(account_config)
