# kavira

[![CI](https://github.com/ostap-mykhaylyak/kavira/actions/workflows/ci.yml/badge.svg)](https://github.com/ostap-mykhaylyak/kavira/actions/workflows/ci.yml)

Enterprise secure mail server in Go: a modern, single-binary
alternative to Postfix + Dovecot + Rspamd, designed for hosting
providers, multi-domain mail hosting, dedicated servers, VPS and
LXD/LXC containers.

**Secure by default**: kavira can never be an open relay, a spam relay
or an abusive SMTP proxy. Anything not explicitly enabled stays off,
and an insecure configuration (e.g. the admin API without keys) is a
startup error, not a warning.

## Status

**M6 — containers and diagnostics** (current): an LXD/LXC deployment
is indistinguishable from one on the metal — the banner, the EHLO
name, the trace headers and even the Maildir filenames carry the
configured public identity, and internal source addresses are
replaced by `container.public_ip` in outgoing headers while public
ones stay traceable. Three diagnostic commands: `audit` (local
configuration and file permissions, no network), `security-check`
(a real open-relay attempt against the running server, TLS, MX/SPF/
DKIM/DMARC with the published key compared to the local one, reverse
DNS, blacklists) and `container-check`. All three exit non-zero on
failure, so they drop straight into monitoring.

**M5 — antispam, reputation, admin API**: a Bayesian
classifier trained on the operator's own corpus (persisted, combined
in log space so long messages cannot underflow) plus heuristics over
headers, links and attachments; executable attachments are refused
outright and a double extension is flagged as the disguise it is.
ClamAV over its socket (INSTREAM, no temp files): a virus is never
delivered, not even quarantined. DNSBL for connecting IPs and URIBL
for body links, cached and ignoring answers outside 127.0.0.0/8 so a
hijacking resolver cannot condemn every sender. Outbound reputation
per user and domain (0..100, decaying toward the baseline) with a
warm-up ramp that caps a new domain's daily volume. Administrative
HTTPS API with static API keys only — constant-time comparison, rate
limited, never exposing password material, and `/health` as the sole
unauthenticated endpoint. Prometheus metrics are deliberately not
implemented yet.

**M4 — IMAP and POP3**: IMAP4rev1 (RFC 3501) on 143
(STARTTLS) and 993, with IDLE (RFC 2177), UIDPLUS and MOVE
(RFC 6851): SELECT/EXAMINE, FETCH (ENVELOPE, BODY[…] sections,
HEADER.FIELDS, peek semantics), STORE, SEARCH, COPY, APPEND, EXPUNGE,
LIST/STATUS/CREATE/DELETE. POP3 (RFC 1939) on 110 (STLS) and 995 with
USER/PASS, STAT, LIST, UIDL, RETR, TOP, DELE, RSET — deletions applied
only at QUIT, as the UPDATE state requires. Both refuse credentials on
a plaintext channel (IMAP advertises LOGINDISABLED) and neither
listener starts without a certificate. Messages carry stable UIDs and
a persisted UIDVALIDITY; Maildir flags map onto IMAP system flags.

**M3 — SPF, DKIM, DMARC**: inbound pipeline on port 25 —
SPF (RFC 7208, full evaluation incl. macros), DKIM verification
(RFC 6376), DMARC (RFC 7489) with relaxed/strict alignment on the
organizational domain (public suffix list). Every message gets an
Authentication-Results header (RFC 8601); DMARC p=reject answers 550
at DATA, p=quarantine delivers into the Maildir++ `.Spam` folder,
sp=/pct= honored. Outbound: submission messages are DKIM-signed
(relaxed/relaxed, RSA 2048) when the sender domain has a key;
`kavira generate-dkim <domain>` creates it and prints the DNS record.
A DNS temporary failure degrades to accept: mail is not lost over a
flaky resolver.

**M2 — submission and outbound**: authenticated submission
on 587 (STARTTLS) and 465 (implicit TLS) with AUTH PLAIN/LOGIN over
TLS only, Argon2id/bcrypt password hashes (never cleartext), brute
force protection (progressive delays + user/IP lockout), envelope
sender enforced to the authenticated user, per-user outbound quotas
(messages/recipients per hour). Disk-backed outbound queue with MX
lookup, opportunistic STARTTLS, exponential retry on 4xx and RFC 3464
bounces on 5xx or exhausted retries.

Already in place — M1: port 25 receives mail for the hosted domains
with structural anti open relay (a recipient is either a local mailbox
or the transaction is refused — there is no relay code path on 25),
STARTTLS, Maildir delivery for system users and virtual mailboxes,
per-IP token bucket rate limiting, VRFY/EXPN permanently disabled.
M0: lifecycle, YAML config with SIGHUP reload, JSON logging, TLS/SNI
wildcard certificate store, CLI, systemd unit.

| Milestone | Scope | Status |
|-----------|-------|--------|
| M0 | scaffolding, config, logging, TLS/SNI, CLI, systemd | done |
| M1 | SMTP inbound (25), anti-relay, Maildir delivery, inbound rate limit | done |
| M2 | AUTH, submission (465/587), outbound queue, retry, bounce | done |
| M3 | SPF, DKIM (sign+verify), DMARC | done |
| M4 | IMAP4rev1 (IDLE), POP3 | done |
| M5 | antispam, reputation, warm-up, blacklist monitoring, API | done (metrics deferred) |
| M6 | LXD/LXC container identity, security-check, audit | done |

## Build

Go >= 1.26. Static binaries for Linux:

```sh
make            # bin/kavira        (linux amd64)
make release    # + bin/kavira-arm64 (linux arm64)
make test
```

## Install (Linux)

From a release — static binaries, no dependencies:

```sh
VERSION=v0.1.0
curl -LO https://github.com/ostap-mykhaylyak/kavira/releases/download/$VERSION/kavira-$VERSION-linux-amd64
curl -LO https://github.com/ostap-mykhaylyak/kavira/releases/download/$VERSION/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
install -m 0755 kavira-$VERSION-linux-amd64 /usr/sbin/kavira
```

Or from source:

```sh
make install
```

Then, either way:

```sh
# review /etc/kavira/config.yaml, then:
kavira check-config
systemctl daemon-reload
systemctl enable --now kavira
```

On first start without a config, kavira provisions the default layout
(`/etc/kavira`, `/var/log/kavira`, `/var/lib/kavira`) by itself.

Releases carry `linux-amd64` and `linux-arm64` binaries, the systemd
unit and a sample configuration; every tag is built by CI only after
the full test suite passes.

## CLI

```
kavira start           run the daemon in the foreground (systemd)
kavira stop            signal the running daemon to shut down
kavira reload          reload config, certificates and log files
kavira check-config    validate the configuration and exit
kavira hash-password   read a password from stdin, print argon2id hash
kavira generate-dkim   create a domain's DKIM key, print the DNS record
kavira version         print version and exit
```

```
kavira audit            local config and permissions, no network
kavira security-check   probe the live deployment (relay, TLS, DNS, rDNS)
kavira container-check  verify a containerized deployment's public identity
```

The diagnostics exit 1 when a check fails (warnings alone do not), so
they can be wired into monitoring directly. `security-check` needs the
daemon running; `--host` points the probe somewhere other than
`server.hostname`, which is what you want during installation.

## Configuration

`/etc/kavira/config.yaml` — see the commented example in
[internal/bootstrap/skel/etc/kavira/config.yaml](internal/bootstrap/skel/etc/kavira/config.yaml).
Reload without restart: `kavira reload` (SIGHUP). A broken config is
never applied: the previous one stays active and the error is logged.

### TLS certificates

Certificates are **wildcards issued on the configured domain**, in the
standard Let's Encrypt layout — never a per-subdomain directory:

```
mail.example.com       -> /etc/letsencrypt/live/example.com/
mail.studenti.ente.it  -> /etc/letsencrypt/live/studenti.ente.it/
```

The "base domain" is exactly the domain declared in `domains:` — no
heuristics. SNI resolves the client-sent name to the longest configured
domain suffix (so `studenti.ente.it` wins over `ente.it` when both are
configured). TLS floor is 1.2 (configurable to 1.3); SSLv3/1.0/1.1 are
never offered. Renewed certificates are picked up on `kavira reload`
and automatically every 12 hours.

## Mail access

Mailboxes are plain Maildirs, readable by any standard tool. IMAP
folders follow the Maildir++ convention: `INBOX` is the account root,
every other folder is a `.` prefixed subdirectory (`.Sent`,
`.Spam`, …), and the hierarchy delimiter is `.`.

Each folder keeps a `kavira-uidlist` file mapping the message's stable
Maildir name to its IMAP UID, plus the mailbox UIDVALIDITY. Losing or
corrupting that file is safe: kavira mints a fresh UIDVALIDITY, which
tells clients to resynchronize instead of trusting a stale cache.

## Running in a container

Kavira is meant to be indistinguishable from a server on the metal.
Set `server.hostname` to the public FQDN — never the container's own
name — and declare the addresses:

```yaml
container:
  enabled: true
  type: lxd
  public_ip: "203.0.113.10"
  internal_ip: "10.1.0.20"
```

With this in place, a source address on the internal bridge (a webmail
submitting through kavira, for instance) is recorded in trace headers
as the public IP, so relayed mail never carries the host's private
topology. Public sender addresses are left untouched: the real origin
of inbound mail stays traceable. `kavira container-check` verifies all
of it, including that the hostname is not something like
`container01.lxd`.

Kavira takes no backups of its own. Snapshot the mail storage, the
queue and the DKIM keys with LXD or ZFS snapshots, and keep a copy of
the configuration.

## Administrative API

HTTPS with static API keys (no JWT), presented as
`Authorization: Bearer <key>` or `X-API-Key: <key>`:

```
GET  /health              liveness, no authentication
GET  /api/v1/status       version, uptime, domain/user counts, queue depth
GET  /api/v1/domains      configured domains
GET  /api/v1/users        mailboxes (never any password material)
GET  /api/v1/reputation   sender scores, worst first
POST /api/v1/reload       re-read the configuration
```

Enabling the API without keys is a startup error, and the listener
does not start without a certificate.

## Spam filtering

The Bayesian classifier starts with no opinion and stays silent until
it has seen at least 20 ham and 20 spam messages — an untrained filter
guessing from a handful of examples is worse than no filter. Train it
by feeding messages through the corpus file at `antispam.bayes_file`.

Scores drive three escalating thresholds (`tag_score` ≤
`quarantine_score` ≤ `reject_score`; the config refuses any other
order): tag stamps `X-Spam-Status`, quarantine delivers into `.Spam`,
reject answers 550 at DATA. Executable attachments and confirmed
malware bypass the score entirely and are refused outright.

## Logging

JSON lines in `/var/log/kavira/kavira.log`. Rotation is delegated to
logrotate; SIGHUP reopens the files.

## DNS records

```
; MX
example.com.            IN MX 10 mail.example.com.
mail.example.com.       IN A     203.0.113.10

; SPF
example.com.            IN TXT   "v=spf1 mx -all"

; DKIM — `kavira generate-dkim example.com` prints this record
default._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=<public-key>"

; DMARC
_dmarc.example.com.     IN TXT   "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com"
```

The PTR record of the public IP must resolve to `server.hostname`.

### DKIM signing

Outbound mail is signed automatically once a domain has a key:

```sh
kavira generate-dkim example.com     # writes the key, prints the TXT record
kavira reload                        # not even needed: keys are read per message
```

Keys live in `/var/lib/kavira/dkim/<domain>/<selector>.pem` (mode
0600, `dkim.dir` in the config). `generate-dkim` never overwrites an
existing key: run against a domain that already has one, it re-prints
the published record instead. A domain without a key simply sends
unsigned — signing is never a delivery blocker.
