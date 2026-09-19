import unittest
from pathlib import Path

from mailwarden.message import ParsedMessage
from mailwarden.rules.engine import Engine, RuleSet

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> ParsedMessage:
    raw = (FIXTURES / name).read_bytes()
    return ParsedMessage.from_bytes(raw, provider_id=name)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(ruleset=RuleSet.load(), dnsbl_enabled=False)

    def test_obvious_spam_is_flagged(self):
        verdict = self.engine.score(load("spam1.eml"))
        self.assertTrue(verdict.is_spam, verdict.explain())
        self.assertTrue(verdict.is_high_confidence, verdict.explain())
        fired = {hit.rule for hit in verdict.hits}
        self.assertIn("AUTH_SPF_FAIL", fired)
        self.assertIn("FROM_NAME_SPOOF", fired)
        self.assertIn("REPLY_TO_MISMATCH", fired)
        self.assertIn("SUSPICIOUS_KEYWORD", fired)

    def test_normal_email_is_not_flagged(self):
        verdict = self.engine.score(load("ham1.eml"))
        self.assertFalse(verdict.is_spam, verdict.explain())

    def test_allowlist_overrides_content_score(self):
        engine = Engine(ruleset=RuleSet.load(), dnsbl_enabled=False,
                         allowlist={"security-alert@totally-legit-paypa1.tk"})
        verdict = engine.score(load("spam1.eml"))
        self.assertFalse(verdict.is_spam)

    def test_blocklist_forces_spam(self):
        engine = Engine(ruleset=RuleSet.load(), dnsbl_enabled=False,
                         blocklist={"alex.rivera@example.com"})
        verdict = engine.score(load("ham1.eml"))
        self.assertTrue(verdict.is_spam)


if __name__ == "__main__":
    unittest.main()
