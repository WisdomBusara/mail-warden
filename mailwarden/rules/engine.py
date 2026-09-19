from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..message import ParsedMessage
from . import checks
from .checks import RuleContext

DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.yaml"


@dataclass
class RuleHit:
    rule: str
    score: float
    detail: str


@dataclass
class Verdict:
    score: float
    hits: list[RuleHit]
    is_spam: bool
    is_high_confidence: bool

    def explain(self) -> str:
        lines = [f"score={self.score:.1f} spam={self.is_spam}"]
        for h in sorted(self.hits, key=lambda h: -h.score):
            lines.append(f"  {h.score:+.1f}  {h.rule:<28} {h.detail}")
        return "\n".join(lines)


@dataclass
class RuleSet:
    scores: dict[str, float] = field(default_factory=dict)
    thresholds: dict[str, float] = field(default_factory=dict)
    keywords: list[str] = field(default_factory=list)
    urgent_phrases: list[str] = field(default_factory=list)
    shortener_domains: list[str] = field(default_factory=list)
    executable_extensions: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | str | None = None) -> "RuleSet":
        path = Path(path) if path else DEFAULT_RULES_PATH
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(
            scores=data.get("scores", {}),
            thresholds=data.get("thresholds", {}),
            keywords=data.get("keywords", []),
            urgent_phrases=data.get("urgent_phrases", []),
            shortener_domains=data.get("shortener_domains", []),
            executable_extensions=data.get("executable_extensions", []),
        )

    def score_of(self, rule_name: str) -> float:
        return self.scores.get(rule_name, 1.0)


class Engine:
    def __init__(
        self,
        ruleset: RuleSet | None = None,
        allowlist: set[str] | None = None,
        blocklist: set[str] | None = None,
        known_senders: set[str] | None = None,
        dnsbl_enabled: bool = True,
        dnsbl_zone: str = "zen.spamhaus.org",
    ):
        self.ruleset = ruleset or RuleSet.load()
        self.ctx = RuleContext(
            keywords=self.ruleset.keywords,
            urgent_phrases=self.ruleset.urgent_phrases,
            shortener_domains=self.ruleset.shortener_domains,
            executable_extensions=self.ruleset.executable_extensions,
            allowlist={a.lower() for a in (allowlist or set())},
            blocklist={a.lower() for a in (blocklist or set())},
            known_senders={a.lower() for a in (known_senders or set())},
            dnsbl_enabled=dnsbl_enabled,
            dnsbl_zone=dnsbl_zone,
        )

    def score(self, msg: ParsedMessage) -> Verdict:
        hits: list[RuleHit] = []

        for rule_name, fn in checks.SIMPLE_CHECKS:
            detail = fn(msg, self.ctx)
            if detail:
                hits.append(RuleHit(rule_name, self.ruleset.score_of(rule_name), detail))

        for fn in checks.MULTI_CHECKS:
            for rule_name, detail in fn(msg, self.ctx):
                hits.append(RuleHit(rule_name, self.ruleset.score_of(rule_name), detail))

        keyword_hits = checks.check_keywords(msg, self.ctx)
        if keyword_hits:
            per_hit = self.ruleset.score_of("SUSPICIOUS_KEYWORD")
            cap = self.ruleset.scores.get("KEYWORD_CAP", 4.0)
            total = min(len(keyword_hits) * per_hit, cap)
            hits.append(RuleHit(
                "SUSPICIOUS_KEYWORD", total,
                f"matched {len(keyword_hits)} keyword(s): {', '.join(keyword_hits[:5])}",
            ))

        total_score = sum(h.score for h in hits)
        # An explicit allowlist/blocklist hit is a hard override, not just a
        # heavy weight, so a whitelisted sender can never be re-flagged by
        # unrelated content rules and vice versa.
        allow_hit = any(h.rule == "WHITELISTED_SENDER" for h in hits)
        block_hit = any(h.rule == "BLACKLISTED_SENDER" for h in hits)

        spam_threshold = self.ruleset.thresholds.get("spam", 5.0)
        high_threshold = self.ruleset.thresholds.get("high_confidence", 8.0)

        if allow_hit:
            is_spam = False
        elif block_hit:
            is_spam = True
        else:
            is_spam = total_score >= spam_threshold

        return Verdict(
            score=total_score,
            hits=hits,
            is_spam=is_spam,
            is_high_confidence=is_spam and total_score >= high_threshold,
        )
