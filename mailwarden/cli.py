from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AppConfig
from .message import ParsedMessage
from .providers import build_provider
from .rules.engine import Engine, RuleSet
from .storage import Store


def cmd_scan(args: argparse.Namespace) -> int:
    app_config = AppConfig.load(args.config)
    store = Store(app_config.resolve(app_config.store_path))
    ruleset = RuleSet.load(app_config.resolve(app_config.rules_file)) if app_config.rules_file else RuleSet.load()

    accounts = app_config.accounts
    if args.account:
        accounts = [a for a in accounts if a.name == args.account]
        if not accounts:
            print(f"No account named {args.account!r} in {args.config}", file=sys.stderr)
            return 1

    exit_code = 0
    for account in accounts:
        dry_run = args.dry_run or account.dry_run
        print(f"=== {account.name} ({account.provider}) {'[dry-run]' if dry_run else ''} ===")
        try:
            engine = Engine(
                ruleset=ruleset,
                allowlist=store.allowlist(),
                blocklist=store.blocklist(),
                known_senders=store.known_senders(),
                dnsbl_enabled=app_config.dnsbl_enabled,
                dnsbl_zone=app_config.dnsbl_zone,
            )
            with build_provider(account) as provider:
                for msg in provider.fetch_inbox_messages(limit=args.limit):
                    verdict = engine.score(msg)
                    label = "SPAM" if verdict.is_spam else "ham "
                    print(f"[{label}] {verdict.score:5.1f}  {msg.from_addr:<40} {msg.subject[:60]}")
                    if args.verbose:
                        print("  " + verdict.explain().replace("\n", "\n  "))

                    action_desc = "no action (below threshold)"
                    if verdict.is_spam:
                        action_desc = provider.mark_as_spam(msg, dry_run=dry_run)
                        print(f"  -> {action_desc}")

                    store.record_sender(msg.from_addr)
                    store.log_scan(msg.provider_id, msg.from_addr, msg.subject, verdict.score, verdict.is_spam, action_desc)
        except Exception as e:
            print(f"error scanning account {account.name!r}: {e}", file=sys.stderr)
            exit_code = 1

    return exit_code


def cmd_test_message(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    msg = ParsedMessage.from_bytes(raw, provider_id="local-test")

    ruleset = RuleSet.load(args.rules) if args.rules else RuleSet.load()
    store = Store(args.store) if args.store else None
    engine = Engine(
        ruleset=ruleset,
        allowlist=store.allowlist() if store else set(),
        blocklist=store.blocklist() if store else set(),
        known_senders=store.known_senders() if store else set(),
        dnsbl_enabled=not args.no_dnsbl,
    )
    verdict = engine.score(msg)
    print(f"From: {msg.from_addr}")
    print(f"Subject: {msg.subject}")
    print(verdict.explain())
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    app_config = AppConfig.load(args.config)
    store = Store(app_config.resolve(app_config.store_path))
    entries = store.allowlist() if args.list_type == "allow" else store.blocklist()
    for entry in sorted(entries):
        print(entry)
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    app_config = AppConfig.load(args.config)
    store = Store(app_config.resolve(app_config.store_path))
    store.add_to_list(args.entry, args.list_type)
    print(f"added {args.entry!r} to {args.list_type}list")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    app_config = AppConfig.load(args.config)
    store = Store(app_config.resolve(app_config.store_path))
    store.remove_from_list(args.entry, args.list_type)
    print(f"removed {args.entry!r} from {args.list_type}list")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    app_config = AppConfig.load(args.config)
    store = Store(app_config.resolve(app_config.store_path))
    stats = store.stats()
    print(f"total scanned: {stats['total_scanned']}")
    print(f"flagged spam:  {stats['spam_flagged']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mailwarden", description="Rule-based spam filter for Gmail and IMAP mailboxes.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan configured accounts and act on spam.")
    p_scan.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    p_scan.add_argument("--account", help="Only scan this account (by name)")
    p_scan.add_argument("--limit", type=int, default=None, help="Max messages to scan per account")
    p_scan.add_argument("--dry-run", action="store_true", help="Force dry-run regardless of config")
    p_scan.add_argument("--verbose", "-v", action="store_true", help="Print the full rule breakdown per message")
    p_scan.set_defaults(func=cmd_scan)

    p_test = sub.add_parser("test-message", help="Score a single .eml file for rule debugging.")
    p_test.add_argument("file", help="Path to a .eml file")
    p_test.add_argument("--rules", help="Path to a custom rules YAML file")
    p_test.add_argument("--store", help="Path to a sqlite store, for allow/block/known-sender lookups")
    p_test.add_argument("--no-dnsbl", action="store_true", help="Skip DNSBL lookups (useful offline)")
    p_test.set_defaults(func=cmd_test_message)

    p_list = sub.add_parser("list", help="List entries on the allow/block list.")
    p_list.add_argument("list_type", choices=["allow", "block"])
    p_list.add_argument("--config", default="config.yaml")
    p_list.set_defaults(func=cmd_list)

    p_add = sub.add_parser("add", help="Add an address or domain to the allow/block list.")
    p_add.add_argument("list_type", choices=["allow", "block"])
    p_add.add_argument("entry", help="Email address or bare domain")
    p_add.add_argument("--config", default="config.yaml")
    p_add.set_defaults(func=cmd_add)

    p_remove = sub.add_parser("remove", help="Remove an address or domain from the allow/block list.")
    p_remove.add_argument("list_type", choices=["allow", "block"])
    p_remove.add_argument("entry")
    p_remove.add_argument("--config", default="config.yaml")
    p_remove.set_defaults(func=cmd_remove)

    p_stats = sub.add_parser("stats", help="Show scan totals from the local store.")
    p_stats.add_argument("--config", default="config.yaml")
    p_stats.set_defaults(func=cmd_stats)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
