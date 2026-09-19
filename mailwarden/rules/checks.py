"""Individual spam-signal checks. Each returns a human-readable detail string
when the rule fires, or None when it doesn't. The engine looks up each rule's
score by name from the loaded rule weights.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .. import dnsbl
from ..message import ParsedMessage

HREF_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
IP_HOST_RE = re.compile(r"^https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


@dataclass
class RuleContext:
    """Config + local state a check may need, beyond the message itself."""
    keywords: list[str] = field(default_factory=list)
    urgent_phrases: list[str] = field(default_factory=list)
    shortener_domains: list[str] = field(default_factory=list)
    executable_extensions: list[str] = field(default_factory=list)
    allowlist: set[str] = field(default_factory=set)   # lowercased email addresses or domains
    blocklist: set[str] = field(default_factory=set)
    known_senders: set[str] = field(default_factory=set)  # senders seen before (for FIRST_TIME_SENDER)
    dnsbl_enabled: bool = True
    dnsbl_zone: str = "zen.spamhaus.org"


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else addr.lower()


def _in_list(addr: str, entries: set[str]) -> bool:
    addr = addr.lower()
    domain = _domain(addr)
    return addr in entries or domain in entries


# --- structural / header checks -------------------------------------------------

def check_allowlisted(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if msg.from_addr and _in_list(msg.from_addr, ctx.allowlist):
        return f"sender {msg.from_addr} is on the allowlist"
    return None


def check_blocklisted(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if msg.from_addr and _in_list(msg.from_addr, ctx.blocklist):
        return f"sender {msg.from_addr} is on the blocklist"
    return None


def check_missing_date(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if not msg.msg.get("Date"):
        return "no Date header"
    return None


def check_missing_message_id(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if not msg.msg.get("Message-ID"):
        return "no Message-ID header"
    return None


def check_from_name_spoof(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    """Flags a display name that itself looks like an email address on a
    different domain than the actual From address -- a common phishing trick
    (e.g. From: "support@paypal.com" <scammer@evil.tld>)."""
    if not msg.from_name or "@" not in msg.from_name:
        return None
    name_domain = _domain(msg.from_name.strip())
    addr_domain = _domain(msg.from_addr)
    if name_domain and addr_domain and name_domain != addr_domain:
        return f"display name claims {name_domain} but sent from {addr_domain}"
    return None


def check_reply_to_mismatch(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if not msg.reply_to:
        return None
    from email.utils import getaddresses
    reply_addrs = [a for _, a in getaddresses([msg.reply_to]) if a]
    if not reply_addrs:
        return None
    if _domain(reply_addrs[0]) != _domain(msg.from_addr):
        return f"Reply-To domain {_domain(reply_addrs[0])} differs from From domain {_domain(msg.from_addr)}"
    return None


def check_auth_results(msg: ParsedMessage, ctx: RuleContext) -> list[tuple[str, str]]:
    """Parses the Authentication-Results header (stamped by the receiving MTA,
    e.g. Gmail/Outlook) for SPF/DKIM/DMARC verdicts. Returns a list of
    (rule_name, detail) pairs since multiple auth mechanisms can fail at once."""
    header = msg.msg.get("Authentication-Results", "")
    if not header:
        return [("NO_AUTH_RESULTS", "no Authentication-Results header present")]

    hits = []
    for mechanism, rule in (("spf", "AUTH_SPF_FAIL"), ("dkim", "AUTH_DKIM_FAIL"), ("dmarc", "AUTH_DMARC_FAIL")):
        m = re.search(rf"{mechanism}=(\w+)", header, re.IGNORECASE)
        if m and m.group(1).lower() in ("fail", "softfail", "permerror"):
            hits.append((rule, f"{mechanism}={m.group(1)}"))
    return hits


def check_dnsbl(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if not ctx.dnsbl_enabled:
        return None
    ips = msg.received_ips()
    for ip in ips:
        if dnsbl.is_listed(ip, zone=ctx.dnsbl_zone):
            return f"sending IP {ip} listed on {ctx.dnsbl_zone}"
    return None


def check_first_time_sender(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if msg.from_addr and msg.from_addr.lower() not in ctx.known_senders:
        return f"first message seen from {msg.from_addr}"
    return None


# --- content checks ---------------------------------------------------------------

def check_subject_all_caps(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    letters = [c for c in msg.subject if c.isalpha()]
    if len(letters) >= 6 and sum(1 for c in letters if c.isupper()) / len(letters) > 0.8:
        return f"subject is mostly uppercase: {msg.subject!r}"
    return None


def check_excessive_exclamation(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    count = msg.subject.count("!") + msg.text_body.count("!")
    if count >= 3:
        return f"{count} exclamation marks across subject/body"
    return None


def check_keywords(msg: ParsedMessage, ctx: RuleContext) -> list[str]:
    haystack = (msg.subject + "\n" + msg.text_body + "\n" + msg.html_body).lower()
    return [kw for kw in ctx.keywords if kw.lower() in haystack]


def check_urgent_language(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    haystack = (msg.subject + "\n" + msg.text_body).lower()
    hits = [p for p in ctx.urgent_phrases if p.lower() in haystack]
    if hits:
        return f"urgency phrasing: {', '.join(hits[:3])}"
    return None


def check_shortened_urls(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    for url in msg.urls:
        for domain in ctx.shortener_domains:
            if f"//{domain}".lower() in url.lower():
                return f"shortened URL via {domain}"
    return None


def check_ip_literal_urls(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    for url in msg.urls:
        if IP_HOST_RE.match(url):
            return f"link points directly at an IP address: {url}"
    return None


def check_link_text_mismatch(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    """Flags anchor text that looks like a URL/domain different from where the
    link actually goes -- classic phishing ("click here" links are fine; a
    link whose *text* claims paypal.com but whose href goes elsewhere is not)."""
    if not msg.html_body:
        return None
    for href, text in HREF_RE.findall(msg.html_body):
        visible = TAG_RE.sub("", text).strip()
        text_domain_m = re.search(r"([a-z0-9-]+\.[a-z]{2,})", visible, re.IGNORECASE)
        href_domain_m = re.search(r"https?://([^/\s]+)", href, re.IGNORECASE)
        if text_domain_m and href_domain_m:
            text_domain = text_domain_m.group(1).lower()
            href_domain = href_domain_m.group(1).lower()
            if text_domain != href_domain and not href_domain.endswith("." + text_domain):
                return f"link text says {text_domain} but href points to {href_domain}"
    return None


def check_attachments(msg: ParsedMessage, ctx: RuleContext) -> list[tuple[str, str]]:
    hits = []
    for filename, _content_type in msg.attachments:
        lower = filename.lower()
        ext_hits = [ext for ext in ctx.executable_extensions if lower.endswith(ext)]
        if ext_hits:
            hits.append(("EXECUTABLE_ATTACHMENT", f"attachment {filename!r} has executable extension {ext_hits[0]}"))
        # e.g. "invoice.pdf.exe" -- two extensions where the last is executable
        parts = lower.rsplit(".", 2)
        if len(parts) == 3 and f".{parts[2]}" in ctx.executable_extensions:
            hits.append(("DOUBLE_EXTENSION_ATTACHMENT", f"attachment {filename!r} disguises its real extension"))
    return hits


def check_html_only(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    if msg.html_body and not msg.text_body.strip():
        return "HTML-only body with no plaintext alternative"
    return None


def check_unsubscribe_without_header(msg: ParsedMessage, ctx: RuleContext) -> Optional[str]:
    body = (msg.text_body + msg.html_body).lower()
    if "unsubscribe" in body and not msg.msg.get("List-Unsubscribe"):
        return "mentions unsubscribing in the body but has no List-Unsubscribe header"
    return None


# Rules producing a single optional hit.
SIMPLE_CHECKS: list[tuple[str, Callable[[ParsedMessage, RuleContext], Optional[str]]]] = [
    ("WHITELISTED_SENDER", check_allowlisted),
    ("BLACKLISTED_SENDER", check_blocklisted),
    ("MISSING_DATE", check_missing_date),
    ("MISSING_MESSAGE_ID", check_missing_message_id),
    ("FROM_NAME_SPOOF", check_from_name_spoof),
    ("REPLY_TO_MISMATCH", check_reply_to_mismatch),
    ("DNSBL_LISTED", check_dnsbl),
    ("FIRST_TIME_SENDER", check_first_time_sender),
    ("SUBJECT_ALL_CAPS", check_subject_all_caps),
    ("EXCESSIVE_EXCLAMATION", check_excessive_exclamation),
    ("URGENT_LANGUAGE", check_urgent_language),
    ("SHORTENED_URL", check_shortened_urls),
    ("IP_LITERAL_URL", check_ip_literal_urls),
    ("LINK_TEXT_MISMATCH", check_link_text_mismatch),
    ("HTML_ONLY_NO_TEXT", check_html_only),
    ("UNSUBSCRIBE_NO_LIST_HEADER", check_unsubscribe_without_header),
]

# Rules that can produce zero or more hits (multi-value).
MULTI_CHECKS: list[Callable[[ParsedMessage, RuleContext], list]] = [
    check_auth_results,
    check_attachments,
]
