# MailWarden

A rule-based spam filter for Gmail and generic IMAP mailboxes (Outlook,
Yahoo, iCloud, self-hosted), modeled on Apache SpamAssassin's approach:
many small, independent signals are scored and summed, and a threshold
decides the verdict. It runs as a standalone script/scheduled job against
your own mail accounts — it does not depend on any chat session.

## How it decides

Each message is scored against rules like:

- **Authentication**: SPF/DKIM/DMARC failures (read from the
  `Authentication-Results` header your provider already stamps)
- **Header spoofing**: display-name/From-domain mismatches, Reply-To domain
  mismatches, missing Date/Message-ID
- **DNSBL**: sending IP checked against Spamhaus ZEN (or any DNSBL you configure)
- **Content**: spam keyword/phrase lists, urgency language, ALL-CAPS subjects,
  excessive punctuation
- **Links**: shortened URLs, IP-literal links, anchor text that lies about
  its destination domain
- **Attachments**: executable extensions, double-extension disguises
- **Sender history**: first-time senders, plus your own allow/block lists
  (which are hard overrides, not just extra weight)

All weights, keywords, and thresholds live in
[`mailwarden/rules/default_rules.yaml`](mailwarden/rules/default_rules.yaml) — copy and tune it
rather than editing code, and point `rules_file` at your copy in `config.yaml`.

## Setup

```
pip install -r requirements.txt
cp config.example.yaml config.yaml
```

Edit `config.yaml` for each account you want scanned. Two provider types:

### Gmail

1. In [Google Cloud Console](https://console.cloud.google.com/), create a project,
   enable the **Gmail API**, and create an OAuth client of type **Desktop app**.
2. Download its JSON as `credentials.json`, referenced by `credentials_file`.
3. First run opens a browser for consent; the token is cached at `token_file`
   so later runs are unattended.
4. Leave `dry_run: true` until you've reviewed a few scans — it logs what it
   *would* do without touching your mail.

### IMAP (Outlook, Yahoo, iCloud, etc.)

Set `host`, `username`, and `password_env` (an environment variable name —
never put a literal password in `config.yaml`). Most providers require an
**app password** once 2FA is enabled; generate one in that provider's
security settings.

```
$env:MAILWARDEN_OUTLOOK_PASSWORD = "your-app-password"   # PowerShell
```

## Usage

```
# Score-only dry run across every configured account
python -m mailwarden scan --dry-run -v

# Scan one account for real, once you trust the scoring
python -m mailwarden scan --account personal-gmail

# Debug scoring against a single .eml file, no account needed
python -m mailwarden test-message path/to/message.eml

# Maintain your allow/block lists (hard overrides in scoring)
python -m mailwarden add allow trusted-sender@example.com
python -m mailwarden add block spammer@example.net
python -m mailwarden list block

# Totals from the local scan log
python -m mailwarden stats
```

Run `scan` on a schedule (Windows Task Scheduler, cron, a cloud function)
for hands-off operation.

## Actions

Each account sets `action` to one of:

- `label` (Gmail) / `move` (IMAP) — the default; tags the message and
  removes it from the inbox, fully reversible
- `trash` — moves to Trash/Deleted Items
- `delete` — **permanent**, only takes effect if you also set
  `allow_permanent_delete: true`; otherwise it safely falls back to `trash`/`move`

## Safety notes

- Every rule fails open: if a lookup errors (e.g. no network for DNSBL), it
  simply doesn't contribute to the score rather than blocking the scan.
- `WHITELISTED_SENDER`/`BLACKLISTED_SENDER` are hard overrides — an allowed
  sender is never re-flagged by content rules, and vice versa.
- Start every new account with `dry_run: true` and `-v`, review the output,
  then flip `dry_run` off.

## Tests

```
python -m unittest discover -s tests -v
```
