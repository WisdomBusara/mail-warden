"""Gmail backend using the Gmail API (OAuth2, installed-app flow).

Setup:
  1. In Google Cloud Console, create a project, enable the Gmail API, and
     create an OAuth "Desktop app" client. Download the JSON as credentials.json.
  2. Point `credentials_file` at it in your account config.
  3. First run opens a browser for consent; the resulting token is cached at
     `token_file` so later runs are unattended.
"""
from __future__ import annotations

import base64
from typing import Iterator, Optional

from ..message import ParsedMessage
from .base import MailProvider

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


class GmailProvider(MailProvider):
    def __init__(self, account_config):
        super().__init__(account_config)
        self._service = None
        self._label_cache: dict[str, str] = {}

    def connect(self) -> None:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
        except ImportError as e:
            raise RuntimeError(
                "Gmail support requires google-api-python-client, google-auth-httplib2, "
                "and google-auth-oauthlib. Install with:\n"
                "  pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
            ) from e

        from pathlib import Path
        creds = None
        token_file = Path(self.config.get("token_file", "token.json"))
        credentials_file = Path(self.config.get("credentials_file", "credentials.json"))

        if token_file.exists():
            creds = Credentials.from_authorized_user_file(str(token_file), SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not credentials_file.exists():
                    raise FileNotFoundError(
                        f"Gmail OAuth client secret not found at {credentials_file}. "
                        "Download it from Google Cloud Console (OAuth client, Desktop app type)."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
                creds = flow.run_local_server(port=0)
            token_file.write_text(creds.to_json(), encoding="utf-8")

        self._service = build("gmail", "v1", credentials=creds)

    def fetch_inbox_messages(self, limit: Optional[int] = None) -> Iterator[ParsedMessage]:
        query = self.config.get("query", "in:inbox")
        request = self._service.users().messages().list(userId="me", q=query, maxResults=min(limit or 100, 500))
        fetched = 0
        while request is not None:
            response = request.execute()
            for item in response.get("messages", []):
                if limit and fetched >= limit:
                    return
                raw_msg = self._service.users().messages().get(
                    userId="me", id=item["id"], format="raw"
                ).execute()
                raw_bytes = base64.urlsafe_b64decode(raw_msg["raw"])
                yield ParsedMessage.from_bytes(raw_bytes, provider_id=item["id"], folder="INBOX")
                fetched += 1
            request = self._service.users().messages().list_next(request, response)

    def _get_or_create_label(self, name: str) -> str:
        if name in self._label_cache:
            return self._label_cache[name]

        labels = self._service.users().labels().list(userId="me").execute().get("labels", [])
        for label in labels:
            if label["name"] == name:
                self._label_cache[name] = label["id"]
                return label["id"]

        created = self._service.users().labels().create(
            userId="me",
            body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"},
        ).execute()
        self._label_cache[name] = created["id"]
        return created["id"]

    def mark_as_spam(self, msg: ParsedMessage, dry_run: bool) -> str:
        action = self.config.action
        spam_label = self.config.get("spam_label", "MailWarden/Spam")
        remove_inbox = self.config.get("remove_from_inbox", True)

        if action in ("label", "move"):
            description = f"add label {spam_label!r}" + (" and remove from INBOX" if remove_inbox else "")
            if dry_run:
                return f"[dry-run] would {description} on {msg.provider_id}"
            label_id = self._get_or_create_label(spam_label)
            body = {"addLabelIds": [label_id]}
            if remove_inbox:
                body["removeLabelIds"] = ["INBOX"]
            self._service.users().messages().modify(userId="me", id=msg.provider_id, body=body).execute()
            return f"{description} on {msg.provider_id}"

        if action == "trash":
            if dry_run:
                return f"[dry-run] would trash {msg.provider_id}"
            self._service.users().messages().trash(userId="me", id=msg.provider_id).execute()
            return f"trashed {msg.provider_id}"

        if action == "delete":
            if not self.config.get("allow_permanent_delete", False):
                # Permanent delete needs explicit opt-in; trash is the safe default.
                if dry_run:
                    return f"[dry-run] would trash {msg.provider_id} (permanent delete not enabled)"
                self._service.users().messages().trash(userId="me", id=msg.provider_id).execute()
                return f"trashed {msg.provider_id} (permanent delete not enabled)"
            if dry_run:
                return f"[dry-run] would PERMANENTLY delete {msg.provider_id}"
            self._service.users().messages().delete(userId="me", id=msg.provider_id).execute()
            return f"permanently deleted {msg.provider_id}"

        raise ValueError(f"Unknown action {action!r}")

    def close(self) -> None:
        self._service = None
