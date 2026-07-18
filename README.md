# kavira

[![CI](https://github.com/ostap-mykhaylyak/kavira/actions/workflows/ci.yml/badge.svg)](https://github.com/ostap-mykhaylyak/kavira/actions/workflows/ci.yml)

Enterprise mail server in Go. A single static binary that replaces
Postfix, Dovecot and Rspamd: SMTP, IMAP and POP3, sender
authentication, spam and virus filtering, outbound reputation
management, and an administrative API.

Built for hosting providers, multi-domain mail hosting, dedicated
servers, VPS and LXD/LXC containers.

---

## Contents

- [Design principles](#design-principles)
- [Installation](#installation)
- [Configuration layout](#configuration-layout)
- [Domains and mailboxes](#domains-and-mailboxes)
- [TLS certificates](#tls-certificates)
- [SMTP](#smtp)
- [Authentication and submission](#authentication-and-submission)
- [IMAP and POP3](#imap-and-pop3)
- [Outbound queue](#outbound-queue)
- [SPF, DKIM and DMARC](#spf-dkim-and-dmarc)
- [Spam filtering](#spam-filtering)
- [Antivirus](#antivirus)
- [Blacklists](#blacklists)
- [Rate limiting](#rate-limiting)
- [Reputation and warm-up](#reputation-and-warm-up)
- [Administrative API](#administrative-api)
- [Running in a container](#running-in-a-container)
- [Logging](#logging)
- [Diagnostics](#diagnostics)
- [Command reference](#command-reference)
- [DNS records](#dns-records)
- [Building](#building)

---

## Design principles

**Secure by default.** Kavira cannot be configured into an open relay:
on port 25 a recipient is either a local mailbox or the transaction is
refused, and no code path exists that would relay it. Authentication
is offered only over TLS. Anything not explicitly enabled stays off,
and an insecure configuration — the admin API without keys, spam
thresholds in the wrong order, a container without a public address —
is a startup error, not a warning.

**Operable.** Every subsystem writes structured JSON events. Three
diagnostic commands verify the deployment against reality, including a
real open-relay attempt against the running server. A broken domain
file takes down that domain, not the server.

**Single binary.** Static, no runtime dependencies, `amd64` and
`arm64`.

---

## Installation

From a release:

```sh
VERSION=v0.1.0
curl -LO https://github.com/ostap-mykhaylyak/kavira/releases/download/$VERSION/kavira-$VERSION-linux-amd64
curl -LO https://github.com/ostap-mykhaylyak/kavira/releases/download/$VERSION/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
install -m 0755 kavira-$VERSION-linux-amd64 /usr/sbin/kavira
```

Then provision the filesystem layout, the default configuration and
the systemd unit:

```sh
kavira init
```

`init` creates `/etc/kavira` with its `domains/` directory,
`/var/log/kavira`, `/var/lib/kavira` with the queue and DKIM
directories, writes a commented configuration and an example domain
file, and installs the unit. It never overwrites an existing file, so
running it twice is safe.

Follow the printed steps, then:

```sh
kavira check-config
systemctl daemon-reload
systemctl enable --now kavira
kavira audit && kavira security-check
```

To remove everything kavira owns — configuration, domains, logs,
queue, DKIM keys, learned spam corpus and the unit:

```sh
kavira purge          # lists what it will delete and asks first
kavira purge --yes    # unattended
```

Purge destroys the DKIM private keys and every queued message, so it
requires the confirmation to be typed in full. Mailboxes outside those
paths are not touched.

Building from source is described in [Building](#building).

---

## Configuration layout

```
/etc/kavira/
├── config.yaml                    the server: listeners, TLS, policy
└── domains/
    ├── example.com.yaml           one file per hosted domain
    └── studenti.ente.it.yaml
```

Domains live outside the main configuration deliberately. Adding a
customer, changing one mailbox password or handing a domain to a
provisioning script must not mean rewriting the file that also holds
the listeners and the TLS settings — and a syntax error in one
customer's file must not take the whole server down. A domain file
that fails to parse is logged and skipped; every other domain keeps
working.

Apply any change with `kavira reload` (or `systemctl reload kavira`).
A configuration that fails to load is never applied: the previous one
stays active and the error is logged.

The directory can be moved:

```yaml
# /etc/kavira/config.yaml
domains_dir: /etc/kavira/domains
```

When unset it resolves next to the configuration file, which keeps a
staging copy self-contained.

---

## Domains and mailboxes

One file per domain. **The file name is the domain**: kavira refuses a
file whose `name` key disagrees with it, so a typo cannot silently
create a domain nobody meant to host.

### Virtual mailboxes

```yaml
# /etc/kavira/domains/example.com.yaml
name: example.com
dkim_selector: default

storage:
  type: virtual

users:
  - email: admin@example.com
    maildir: /var/mail/example.com/admin
    password_hash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$..."

  - email: info@example.com
    maildir: /var/mail/example.com/info
    password_hash: "$argon2id$v=19$m=65536,t=3,p=4$..."
```

### System-user mailboxes

A domain can map to one real Linux account. Mail is delivered to that
account's Maildir with its UID and GID, honouring POSIX permissions:

```yaml
# /etc/kavira/domains/ostap.dev.yaml
name: ostap.dev

storage:
  type: system_user
  user: ostap
  home: /home/ostap        # optional, defaults to /home/<user>
  maildir: "{home}/mail"   # optional, {home} expands
  password_hash: "$argon2id$..."
```

Mail for `ostap@ostap.dev` lands in `/home/ostap/mail/{cur,new,tmp}`.
Only the bound account exists in that domain; any other recipient is
rejected with `550`.

### Passwords

Never stored in clear. Generate a hash with:

```sh
kavira hash-password        # reads from stdin, prints an argon2id hash
```

Argon2id (RFC 9106 parameters) and bcrypt are accepted; any other
format is refused at load time. A mailbox without a `password_hash`
can receive mail, but nobody can log in to it — which is exactly what
you want for a catch-all or an alias target.

---

## TLS certificates

Certificates are **wildcards issued on the configured domain**, in the
standard Let's Encrypt layout. There is never a per-subdomain
directory:

```
mail.example.com        →  /etc/letsencrypt/live/example.com/
mail.studenti.ente.it   →  /etc/letsencrypt/live/studenti.ente.it/
```

```yaml
tls:
  cert_root: /etc/letsencrypt/live
  min_version: "1.2"        # or "1.3"; SSLv3/1.0/1.1 are never offered
  expiry_warn_days: 14
```

The "base domain" is exactly the domain declared in `domains/` — no
heuristics that would get `studenti.ente.it` wrong. SNI resolves the
client-sent name to the longest configured domain suffix, so with both
`ente.it` and `studenti.ente.it` hosted, the more specific one wins.

Renewed certificates are picked up on `kavira reload` and
automatically every 12 hours. A missing certificate is a warning, not
a crash: the domains whose certificates load keep working. The
protocols that carry credentials — submission, IMAP, POP3 and the API
— refuse to start without one.

---

## SMTP

```yaml
listeners:
  smtp:
    address: ":25"          # inbound MX
  submission:
    address: ":587"         # authenticated submission, STARTTLS
  smtps:
    address: ":465"         # authenticated submission, implicit TLS

smtp:
  max_size: 26214400        # 25 MB, advertised via EHLO SIZE
  max_recipients: 100
```

An empty address disables a listener.

Port 25 accepts mail **only for hosted domains**. Anything else gets
`554 5.7.1 relay access denied` — this is structural, not a setting.
`VRFY` and `EXPN` are permanently disabled (user enumeration), and
`AUTH` is refused outright on port 25.

Supported: `EHLO`/`HELO`, `PIPELINING`, `SIZE`, `8BITMIME`,
`SMTPUTF8`, `STARTTLS`.

---

## Authentication and submission

Submission requires authentication, and authentication requires TLS:
`AUTH PLAIN` and `AUTH LOGIN` are advertised only once the channel is
encrypted, so a password never crosses the wire in the clear. The
envelope sender is forced to the authenticated user — a spoofed
`MAIL FROM` is refused with `553` and logged.

```yaml
auth:
  max_failures: 10          # then the user AND the source IP lock out
  lockout_minutes: 15
```

Failed attempts get a progressive delay (250 ms doubling, capped at
4 s) before the reply. An unknown user costs the same time as a wrong
password, so the two cannot be told apart.

---

## IMAP and POP3

```yaml
listeners:
  imap:
    address: ":143"         # STARTTLS
  imaps:
    address: ":993"         # implicit TLS
  pop3:
    address: ":110"         # STLS
  pop3s:
    address: ":995"         # implicit TLS
```

IMAP4rev1 (RFC 3501) with `IDLE` (RFC 2177) and `MOVE` (RFC 6851):
`SELECT`, `EXAMINE`, `FETCH`, `STORE`, `SEARCH`, `COPY`, `MOVE`,
`EXPUNGE`, `APPEND`, `UID`, `LIST`, `STATUS`, `CREATE`, `DELETE`.
Flags (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft`) are
stored the standard Maildir way, in the file name.

POP3 (RFC 1939): `USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`,
`DELE`, `TOP`, `RSET`, `QUIT`.

UIDs are stable across sessions and never reused, persisted per
mailbox. If that state is ever lost, `UIDVALIDITY` changes so clients
resynchronise instead of silently mapping stale UIDs onto different
messages.

Folders follow Maildir++: `INBOX` is the mailbox root, everything else
is a `.`-prefixed subdirectory (`.Sent`, `.Drafts`, `.Trash`,
`.Spam`).

---

## Outbound queue

```yaml
queue:
  dir: /var/lib/kavira/queue
  max_attempts: 10
```

One JSON envelope per recipient, written atomically, surviving
restarts. Delivery resolves the destination MX (falling back to the
domain itself per RFC 5321) and uses STARTTLS opportunistically.

- **4xx or a network error** → retry with exponential backoff, 1 minute
  doubling to a 4-hour cap.
- **5xx** → immediate bounce (RFC 3464 delivery status notification).
- **Retries exhausted** → bounce.

A message with a null reverse-path is never bounced, which is what
stops two servers from bouncing at each other forever.

---

## SPF, DKIM and DMARC

### Inbound

```yaml
mail_auth:
  enabled: true
  enforce: true     # false: annotate and log, take no action
```

Every message on port 25 is checked and stamped with an
`Authentication-Results` header (RFC 8601):

- **SPF** (RFC 7208), full evaluation including macros. A null
  reverse-path falls back to checking the HELO name.
- **DKIM** verification (RFC 6376).
- **DMARC** (RFC 7489) with relaxed or strict alignment computed on
  the *organizational* domain via the public suffix list, so
  `a.b.example.co.uk` aligns to `example.co.uk`. `sp=` and `pct=` are
  honoured.

With `enforce: true`, `p=reject` answers `550` at DATA and
`p=quarantine` delivers into `.Spam`. A DNS temporary failure degrades
to accept: losing mail to a flaky resolver is worse than delivering
it.

### Outbound

Mail is DKIM-signed automatically once a domain has a key:

```sh
kavira generate-dkim example.com     # prints the DNS TXT record
```

```yaml
dkim:
  dir: /var/lib/kavira/dkim          # <dir>/<domain>/<selector>.pem
```

RSA 2048, relaxed/relaxed canonicalisation. The selector comes from
the domain file (`dkim_selector`, default `default`).
`generate-dkim` never overwrites an existing key — run against a
domain that already has one, it re-prints the published record. A
domain without a key simply sends unsigned: signing is never a
delivery blocker.

`kavira security-check` compares the **published** key against the
local one, because a mismatch makes every signature fail and nothing
else would notice.

---

## Spam filtering

```yaml
antispam:
  enabled: true
  bayes_file: /var/lib/kavira/bayes
  tag_score: 5              # stamp X-Spam-Status: Yes
  quarantine_score: 10      # deliver into .Spam
  reject_score: 20          # refuse at DATA with 550
  reject_executables: true
```

The thresholds must escalate (`tag ≤ quarantine ≤ reject`); any other
order is refused at load time, because it would silently invert the
operator's intent.

A **Bayesian classifier** trained on your own corpus, combined with
heuristics over headers, links and attachments: missing `Message-ID`
or `Date`, display-name spoofing (`"servizio@banca.it" <thief@evil>`),
all-caps subjects, raw-IP links, spaced-out text.

The classifier stays silent until it has seen at least 20 ham and 20
spam messages — an untrained filter guessing from a handful of
examples is worse than no filter at all. Probabilities are combined in
log space, so a long message cannot underflow to a nonsensical score,
and ham evidence is weighted double, because a false positive costs
the user far more than a false negative.

Executable attachments (`.exe`, `.scr`, `.js`, `.vbs`, …) are refused
outright whatever the score, and a double extension —
`fattura.pdf.exe`, which a client hiding known extensions shows as
`fattura.pdf` — is flagged as the disguise it is.

---

## Antivirus

```yaml
antivirus:
  enabled: true
  socket: /var/run/clamav/clamd.ctl     # or host:port
  timeout_seconds: 30
  reject_on_error: false                # true: defer when clamd is down
```

ClamAV over its socket using `INSTREAM`: no temporary file is written
and clamd needs no access to the queue. A confirmed virus is **never
delivered**, not even quarantined.

---

## Blacklists

```yaml
blacklist:
  enabled: true
  dnsbl:                    # queried with the connecting IP
    - zen.spamhaus.org
    - b.barracudacentral.org
    - dnsbl.sorbs.net
    - dnsbl-1.uceprotect.net
  uribl:                    # queried with hostnames found in the body
    - dbl.spamhaus.org
    - multi.uribl.com
  reject_listed: false      # true: refuse a listed IP outright
  cache_minutes: 60
```

Answers are cached: list operators rate-limit, and eventually block,
heavy queriers. Only answers in `127.0.0.0/8` count as a listing, so a
wildcard-hijacking resolver cannot condemn every sender. Private and
loopback space is never queried at all — that would leak your internal
topology to the list operator.

Start with `reject_listed: false` and let listings contribute to the
spam score; turn it on once you trust your lists.

---

## Rate limiting

Token buckets, burst equal to the rate, refilling continuously.

```yaml
rate_limit:
  inbound:                  # per source IP, per minute
    ip:
      connections_per_minute: 30
      messages_per_minute: 100
      recipients_per_minute: 500

  outbound:                 # per authenticated user, per hour
    user:
      messages_per_hour: 500
      recipients_per_hour: 1000
```

Inbound limits protect against floods and scans (`421`/`452`).
Outbound limits contain a compromised account: the credentials still
work, but the damage is bounded, and the event is logged.

Either can be disabled explicitly with `enabled: false`, which
`kavira audit` reports as a failure.

---

## Reputation and warm-up

```yaml
reputation:
  enabled: true
  file: /var/lib/kavira/reputation.json
  warmup:
    enabled: true
    day1: 100
    day7: 2000
    full_per_day: 50000
```

Every local sender and domain carries a score from 0 to 100, starting
at 50. Successful deliveries and passing authentication raise it;
bounces, spam complaints, blacklist appearances and anomalous sending
lower it. Scores **decay back toward 50** over time, so an old
incident does not haunt a sender forever and a long-quiet good sender
does not keep a reputation it no longer earns.

A sender whose score collapses is refused with `450` until it
recovers.

Warm-up ramps a new domain's daily allowance along the configured
curve over 30 days. Sending 50 000 messages on day one from a fresh
domain is the fastest way to get an IP blocked; the ramp makes that
impossible by construction.

---

## Administrative API

```yaml
api:
  enabled: true
  address: ":8443"
  keys:
    - "0123456789abcdef0123456789abcdef0123456789abcdef"
```

HTTPS with **static API keys only** — no JWT, no sessions, no refresh
flow. Enabling the API without keys is a startup error, and the
listener does not start without a certificate.

```
GET  /health              liveness, the only unauthenticated endpoint
GET  /api/v1/status       version, uptime, domain/user counts, queue depth
GET  /api/v1/domains      hosted domains
GET  /api/v1/users        mailboxes (never any password material)
GET  /api/v1/reputation   sender scores, worst first
POST /api/v1/reload       re-read the configuration
```

```sh
curl -H "Authorization: Bearer $KEY" https://mail.example.com:8443/api/v1/status
```

`X-API-Key` is accepted as an alternative header. Keys are compared in
constant time, and authentication attempts are rate limited per source
IP so the API cannot be used as a key-guessing oracle. Generate keys
with `openssl rand -hex 32`.

---

## Running in a container

```yaml
container:
  enabled: true
  type: lxd
  public_ip: "203.0.113.10"
  internal_ip: "10.1.0.20"
```

From the outside, a containerized kavira is indistinguishable from one
installed on the metal. The SMTP banner, the EHLO name, the trace
headers and even the Maildir file names carry `server.hostname` and
`public_ip` — never the container's own name, never an address from
the internal bridge:

```
220 mail.example.com ESMTP Kavira          correct
220 container01.lxd ESMTP Kavira           never
```

A source address on the internal network — a webmail submitting
through kavira is the common case — is recorded in outgoing trace
headers as the public IP, so relayed mail never carries your private
topology. Public sender addresses are preserved: the real origin of
inbound mail stays traceable.

Storage works with an internal Maildir, an LXD bind mount or a ZFS
dataset; point the mailbox paths wherever the volume is mounted.

Verify the whole thing with `kavira container-check`.

**Backups are not kavira's job.** Snapshot the mail storage, the queue
and the DKIM keys with LXD or ZFS snapshots, and keep a copy of
`/etc/kavira`.

---

## Logging

```yaml
log:
  dir: /var/log/kavira
```

One JSON object per line:

```json
{"time":"2026-07-18T10:14:06Z","level":"WARN","msg":"relay denied",
 "event":"relay_denied","protocol":"smtp","ip":"203.0.113.99",
 "from":"a@b.org","rcpt":"victim@external.org","action":"reject"}
```

Security-relevant events carry a stable `event` field:
`relay_denied`, `auth_failed`, `auth_locked`, `sender_mismatch`,
`ratelimit`, `ratelimit_out`, `reputation_block`, `blacklist_hit`,
`policy_reject`, `policy_quarantine`, `spam_score`, `mail_auth`,
`message_in`, `message_submitted`, `message_out`, `bounce`.

Rotation is delegated to logrotate; `SIGHUP` reopens the files.

---

## Diagnostics

```sh
kavira audit            local configuration and permissions, no network
kavira security-check   probe the live deployment
kavira container-check  verify a containerized deployment's identity
```

**`audit`** inspects only this machine, so it is safe to run anywhere:
configuration posture, credentials, and file permissions — including
that DKIM private keys are not readable beyond their owner.

**`security-check`** exercises the running server: an actual
open-relay attempt (reading the configuration is not evidence, a `554`
is), `AUTH` refused on port 25, `VRFY`/`EXPN` disabled, TLS
certificates and expiry, MX/SPF/DKIM/DMARC per domain with the
published DKIM key compared to the local one, forward-confirmed
reverse DNS, and the blacklist status of your sending IP. Use
`--host` to probe an address other than `server.hostname`, which is
what you want during installation.

**`container-check`** verifies the public identity end to end,
including a worked example of the address substitution.

All three exit `1` when a check fails — warnings alone do not — so
they drop into monitoring as they are.

---

## Command reference

```
Setup:
  kavira init                    create the layout, config and unit
  kavira purge [--yes]           remove config, domains, logs and state

Service:
  kavira start [--config path]   run in the foreground (what systemd does)
  kavira stop                    signal the running daemon to shut down
  kavira reload                  reload config, domains, certificates, logs

Configuration:
  kavira check-config            validate and summarise, then exit
  kavira hash-password           read a password, print an argon2id hash
  kavira generate-dkim <domain>  create a signing key, print the DNS record

Diagnostics:
  kavira audit
  kavira security-check [--host addr]
  kavira container-check

  kavira version
```

`--init` and `--purge` are accepted as aliases for the corresponding
subcommands.

---

## DNS records

```dns
; MX — mail for the domain arrives here
example.com.                    IN MX    10 mail.example.com.
mail.example.com.               IN A     203.0.113.10

; SPF — who may send as this domain
example.com.                    IN TXT   "v=spf1 mx -all"

; DKIM — printed by: kavira generate-dkim example.com
default._domainkey.example.com. IN TXT   "v=DKIM1; k=rsa; p=MIIBIjANBg..."

; DMARC — what receivers should do when the above fail
_dmarc.example.com.             IN TXT   "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com"
```

The PTR record of the public IP must resolve to `server.hostname`, and
that name must resolve back to the same address. Large receivers check
this before accepting anything; `kavira security-check` verifies it.

---

## Building

Go 1.26 or newer.

```sh
make            # bin/kavira          (linux/amd64, static)
make release    # + bin/kavira-arm64  (linux/arm64, static)
make test       # go test ./... -race
make install    # install binary, config skeleton and unit
```

Releases are built by CI from a tag, after the full suite passes, and
published with the systemd unit, a sample configuration and
`SHA256SUMS`.

---

## Status

Feature-complete against the original specification: SMTP with
structural anti-relay, authenticated submission, IMAP and POP3,
SPF/DKIM/DMARC, spam and virus filtering, blacklists, rate limiting,
reputation with warm-up, the administrative API, container identity
and the diagnostic commands.

Deliberately not implemented yet: Prometheus metrics, ARC (RFC 8617),
OAuth2, full MIME `BODYSTRUCTURE` parsing, and Linux user
authentication via PAM.

## License

See [LICENSE](LICENSE).
