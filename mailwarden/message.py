"""Normalizes raw RFC 822 bytes from any provider into one shape the rule engine scores."""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass
class ParsedMessage:
    raw: bytes
    msg: Message
    provider_id: str  # provider-specific message id, for applying actions later
    folder: str = "INBOX"

    subject: str = ""
    from_addr: str = ""
    from_name: str = ""
    reply_to: str = ""
    to_addrs: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    text_body: str = ""
    html_body: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[tuple[str, str]] = field(default_factory=list)  # (filename, content_type)

    @classmethod
    def from_bytes(cls, raw: bytes, provider_id: str, folder: str = "INBOX") -> "ParsedMessage":
        msg = email.message_from_bytes(raw)
        pm = cls(raw=raw, msg=msg, provider_id=provider_id, folder=folder)
        pm._extract()
        return pm

    def _extract(self) -> None:
        self.subject = self._decode_header("Subject")
        from_pairs = getaddresses([self.msg.get("From", "")])
        if from_pairs:
            self.from_name, self.from_addr = from_pairs[0]
        self.reply_to = self.msg.get("Reply-To", "")
        self.to_addrs = [addr for _, addr in getaddresses([self.msg.get("To", "")]) if addr]

        for key in (
            "Received", "Received-SPF", "Authentication-Results", "DKIM-Signature",
            "Message-ID", "Date", "Return-Path", "X-Mailer", "List-Unsubscribe",
            "Content-Type",
        ):
            val = self.msg.get(key)
            if val:
                self.headers[key] = val

        self._extract_bodies(self.msg)
        self.urls = list(dict.fromkeys(URL_RE.findall(self.text_body + " " + self.html_body)))

    def _extract_bodies(self, msg: Message) -> None:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition") or "")
                filename = part.get_filename()

                if filename and "attachment" in disposition.lower():
                    self.attachments.append((filename, content_type))
                    continue
                if content_type == "text/plain" and not self.text_body:
                    self.text_body += self._decode_part(part)
                elif content_type == "text/html" and not self.html_body:
                    self.html_body += self._decode_part(part)
        else:
            content_type = msg.get_content_type()
            if content_type == "text/html":
                self.html_body = self._decode_part(msg)
            else:
                self.text_body = self._decode_part(msg)

    @staticmethod
    def _decode_part(part: Message) -> str:
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except (LookupError, ValueError):
            return ""

    def _decode_header(self, name: str) -> str:
        from email.header import decode_header

        raw = self.msg.get(name, "")
        try:
            parts = decode_header(raw)
            return "".join(
                p.decode(enc or "utf-8", errors="replace") if isinstance(p, bytes) else p
                for p, enc in parts
            )
        except Exception:
            return raw

    def received_ips(self) -> list[str]:
        """Best-effort extraction of IPv4 addresses from Received headers, earliest hop last."""
        ip_re = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
        ips = []
        for val in self.msg.get_all("Received", []):
            m = ip_re.search(val)
            if m:
                ips.append(m.group(1))
        return ips

    def date(self):
        try:
            return parsedate_to_datetime(self.msg.get("Date", ""))
        except (TypeError, ValueError):
            return None
