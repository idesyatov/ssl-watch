# ssl-watch

[![CI](https://github.com/idesyatov/ssl-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/idesyatov/ssl-watch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/idesyatov/ssl-watch)](https://github.com/idesyatov/ssl-watch/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/idesyatov/ssl-watch)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/idesyatov/ssl-watch)](https://goreportcard.com/report/github.com/idesyatov/ssl-watch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small command-line tool to inspect and monitor SSL/TLS certificates — for one domain, many at once, or a local certificate file. Built for cron/CI: a `-threshold` flag drives exit codes, and `-output json` makes the result machine-readable.

**What it checks**

- Expiry and days remaining, with a `-threshold` warning that drives exit code `2`
- Certificate chain validity (trust, hostname, validity period) — on failure, the reason is classified (untrusted/unanchored root, incomplete chain, expired, hostname) and the issuer trail to the break is shown, so you see **where** trust ends (e.g. a private root impersonating a public CA) without reaching for `openssl`
- Certificate Transparency: warns when a leaf carries **no embedded SCTs** and the chain is untrusted (a sign it is not from a genuine public CA)
- Intermediate that expires **before** the leaf (weakest-link expiry)
- Certificate not valid **yet** (`NotBefore` in the future)
- Hostname coverage (does the cert actually cover the requested name, wildcards included)
- Weak crypto (SHA-1 signature, RSA < 2048) and non-server-auth key usage
- Public key type/size and the negotiated TLS version & cipher
- Certificates behind **STARTTLS** (SMTP/IMAP/POP3/FTP)
- The cert on **every IP** of a domain (`-all-ips`) — catch a load balancer serving a stale/different cert
- **Pinning** (`-pin sha256:…`) — verify the served cert/public-key fingerprint, exit `3` on mismatch (catches MITM, a swapped CA, or an unexpected rotation)

## Quick start

```bash
# Install (Linux & macOS) — detects OS/arch/latest release, verifies the checksum
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | sh

# Check a domain
ssl-watch -domain example.com

# Check several domains at once
ssl-watch -domain a.com,b.com,c.com

# Check the cert on every balancer IP of a domain, and compare them
ssl-watch -domain example.com -all-ips

# Check a specific backend/balancer IP (same SNI, chosen address)
ssl-watch -domain example.com -ipaddr 203.0.113.10

# Inspect a local certificate file
ssl-watch -certfile /path/to/cert.crt

# Print the full certificate chain
ssl-watch -domain example.com -chain

# A mail server certificate via STARTTLS
ssl-watch -domain smtp.example.com -starttls smtp

# Monitoring: exit code 2 if it expires within 30 days
ssl-watch -domain example.com -threshold 30 -short

# Machine-readable output (JSON; an array for multiple domains)
ssl-watch -domain example.com -output json
```

> The commands above cover the basics. Run `ssl-watch -help` for the full flag list, or expand the sections below for installation options, the complete flag reference, more examples, output/JSON details and exit codes.

<details>
<summary><strong>Installation</strong> (script options, pre-built binaries, from source)</summary>

### Install script (Linux & macOS)

The fastest way — one command that detects your OS, architecture and the latest
release automatically, verifies the archive's SHA-256 checksum, then installs the
binary to `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | sh
```

`sudo` is requested only if the install directory is not writable. Override the
target directory or pin a version with environment variables:

```bash
# Install to a custom directory (no sudo needed)
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | BINDIR="$HOME/.local/bin" sh

# Install a specific version
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | VERSION=v1.6.1 sh
```

> Prefer to review before running? Download [`install.sh`](https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh), read it, then run `sh install.sh`.

### Pre-built binaries (manual)

Download an archive for your OS/arch from the [latest release](https://github.com/idesyatov/ssl-watch/releases/latest), extract it and place the binary on your `PATH`. Available builds:

- `linux_amd64`, `linux_arm64`
- `darwin_amd64` (Intel Mac), `darwin_arm64` (Apple Silicon)
- `windows_amd64` (`.zip` archive)

SHA-256 checksums for all archives are published as `checksums.txt` on the same release page.

### From source

```bash
go install github.com/idesyatov/ssl-watch@latest
```

Or clone and build:

```bash
git clone https://github.com/idesyatov/ssl-watch.git
cd ssl-watch
make build
```

</details>

<details>
<summary><strong>Command-line flags</strong></summary>

**Target** (one is required)

- `-domain <domains>` — domain to check, or several comma-separated (e.g. `a.com,b.com`).
- `-domain-file <path>` — read domains from a file, one per line (`-` reads stdin); blank lines and `#` comments are ignored.
- `-certfile <path>` — inspect a local certificate file instead of connecting.

**Connection**

- `-port <port>` — port to connect to (default `443`; with `-starttls` the protocol's default port is used unless overridden).
- `-ipaddr <ipaddr>` — connect to a specific IP (only valid with a single domain).
- `-servername <name>` — SNI and hostname to verify against, overriding the domain (e.g. to check a specific vhost's certificate on a host reached by `-ipaddr`).
- `-starttls <proto>` — upgrade via STARTTLS before reading the certificate: `smtp`, `imap`, `pop3` or `ftp`.
- `-timeout <seconds>` — connection timeout when fetching (default `10`).
- `-cafile <path>` — verify the chain against the roots in this PEM bundle **instead of** the system roots (like `openssl verify -CAfile` / `curl --cacert`). Useful for an internal/corporate/national CA. Cannot be combined with `-insecure`.
- `-insecure` — skip certificate chain verification (e.g. for self-signed certs).

**Output**

- `-output <text|json|prometheus>` — output format (default `text`). `prometheus` emits metrics in the exposition format for a single domain or a batch (not with `-all-ips`/`-certfile`).
- `-short` — print only the number of days remaining.
- `-chain` — print every certificate in the chain (subject, issuer, expiry).
- `-fingerprint` — print the certificate and public-key (SPKI) SHA-256 fingerprints.
- `-pem` — print the served certificate chain as PEM to stdout (single target; replaces the normal report).
- `-export <file>` — write the served certificate chain as PEM to a file.
- `-all-ips` — resolve every address of the domain and check the certificate on each, then report whether they match (single domain only).
- `-4` / `-6` — with `-all-ips`, restrict the check to IPv4 or IPv6 addresses (optional; addresses unreachable from the host are skipped automatically anyway).

**Monitoring**

- `-threshold <days>` — exit with code `2` when days remaining is below this value; `0` disables.
- `-pin sha256:<hex>` — verify the served certificate against a pinned fingerprint; the hex may be the certificate **or** the public-key (SPKI) SHA-256, and the check passes if it matches either. Exits with code `3` on a mismatch. Single target only (one domain, a file, or `-all-ips`).
- `-expect-issuer <substring>` — assert the certificate issuer contains this substring (case-insensitive, matched against the full issuer DN, so it covers CN and O). Exits with code `3` on a mismatch — useful for catching an unexpected CA change. Works for a single domain or a batch.
- `-strict` — treat warnings (not-yet-valid, name mismatch, non-server-auth, intermediate-expires-early, untrusted chain, missing SCTs) as failures and exit `2`. Turns the soft diagnostics into a hard CI/cron gate.

In text mode, when writing to an interactive terminal, the days-remaining value and chain status are colorized (red/yellow/green). Color is disabled automatically when output is piped/redirected or when `NO_COLOR` is set.

Several domains can be checked in one run via comma-separated `-domain` or `-domain-file`. In text mode each is printed as its own block prefixed with `==> <domain>`; in JSON mode the output becomes an array (one object per domain, each tagged with `domain`, and an `{ "domain", "error" }` entry for any that could not be retrieved).

</details>

<details>
<summary><strong>Examples</strong></summary>

```bash
# Check the SSL certificate for a domain
ssl-watch -domain example.com

# Check a local certificate file
ssl-watch -certfile /path/to/certificate.crt

# Specific port / IP address
ssl-watch -domain example.com -port 8443
ssl-watch -domain example.com -ipaddr 192.0.2.1

# Only the number of days remaining
ssl-watch -domain example.com -short

# Skip chain verification (self-signed)
ssl-watch -domain self-signed.example.com -insecure

# Monitoring: exit code 2 if it expires within 30 days
ssl-watch -domain example.com -threshold 30 -short

# Machine-readable JSON
ssl-watch -domain example.com -output json

# Shorter connection timeout (3 seconds)
ssl-watch -domain example.com -timeout 3

# Several domains at once
ssl-watch -domain a.com,b.com,c.com

# A list of domains from a file, or from stdin
ssl-watch -domain-file domains.txt -threshold 30
cat domains.txt | ssl-watch -domain-file -

# A mail server certificate via STARTTLS (defaults to port 587)
ssl-watch -domain smtp.example.com -starttls smtp

# Print every certificate in the chain
ssl-watch -domain example.com -chain

# Show the certificate and public-key (SPKI) SHA-256 fingerprints
ssl-watch -domain example.com -fingerprint

# Pin the certificate (or its public key); exit code 3 on mismatch
ssl-watch -domain example.com -pin sha256:e4134cbc...

# Export the served chain as PEM (to stdout or a file)
ssl-watch -domain example.com -pem | openssl x509 -noout -text
ssl-watch -domain example.com -export chain.pem

# Check the certificate on every resolved IP (load balancers)
ssl-watch -domain example.com -all-ips
```

</details>

<details>
<summary><strong>Output &amp; JSON fields</strong></summary>

### Sample text output

```text
Certificate for github.com
Subject: CN=github.com
Issuer: CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB
SANs: github.com, www.github.com
Serial: E7:CE:CC:3B:13:FB:3B:7B:8A:46:EA:8C:D0:AE:B7:1C
Signature: ECDSA-SHA256
Public key: ECDSA P-256
Valid from: 2026-05-05 00:00:00 +0000 UTC
Expires on: 2026-08-02 23:59:59 +0000 UTC
Days remaining: 45
Used IP address: 140.82.121.4
TLS: TLS 1.3 (TLS_AES_128_GCM_SHA256)
Chain: VALID
```

Problems are surfaced as extra `WARNING:` lines and are **only printed when they apply**,
so a healthy certificate stays clean. Examples:

```text
WARNING: certificate is not valid yet — becomes valid in 3 days (2026-06-22)
WARNING: certificate does not cover "api.shop.example.com"
WARNING: intermediate "R3" expires in 12 days, before the leaf (89 days)
WARNING: certificate is not intended for server authentication
```

A `(weak)` marker is shown next to a SHA-1 signature or an RSA key smaller than 2048 bits.

### JSON output

```bash
ssl-watch -domain github.com -output json
```

```json
{
  "common_name": "github.com",
  "subject": "CN=github.com",
  "issuer": "CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB",
  "sans": ["github.com", "www.github.com"],
  "serial": "E7:CE:CC:3B:13:FB:3B:7B:8A:46:EA:8C:D0:AE:B7:1C",
  "signature_algorithm": "ECDSA-SHA256",
  "public_key": "ECDSA P-256",
  "not_before": "2026-05-05T00:00:00Z",
  "not_after": "2026-08-02T23:59:59Z",
  "days_remaining": 45,
  "used_ip": "140.82.121.4",
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "chain_valid": true
}
```

Field notes:

- `chain_valid` / `chain_error` — omitted for file-loaded certificates and with `-insecure`.
- `chain_error_kind` / `untrusted_issuer` — on a failed chain: the classified reason (`untrusted_root`, `unanchored`, `hostname_mismatch`, `expired`, …) and the issuer the chain could not be anchored to.
- `no_sct` — `true` only when the leaf carries no embedded SCTs (Certificate Transparency).
- `tls_version` / `cipher_suite` — present only for fetched certificates.
- `chain` — the full chain array (`{subject, issuer, not_after, days_remaining}`), present only with `-chain`.
- `fingerprint` / `spki_fingerprint` — the certificate and public-key SHA-256, present only with `-fingerprint` (`fingerprint` is also always present per address under `-all-ips`).
- `pin_match` — present only with `-pin`; `true`/`false` for the pin verdict.
- `chain_expiry_warning` — `{subject, days_remaining}`, only when an intermediate expires before the leaf.
- Problem flags appear (as `true`) **only when the problem exists**: `not_yet_valid`, `name_mismatch`, `not_server_auth`, `weak_signature`, `weak_key`.
- When several domains are checked the output is an array; each element carries an extra `domain` field, and failures appear as `{"domain": "...", "error": "..."}`.

### Checking all addresses (`-all-ips`)

Resolves every A/AAAA record of the domain and checks the certificate on each (same SNI), then reports whether they all serve the same certificate:

```text
example.com — checking 3 address(es)
  203.0.113.10                             e3b0c44298fc1c14  89 days  expires 2026-08-02  VALID
  203.0.113.11                             e3b0c44298fc1c14  89 days  expires 2026-08-02  VALID
  203.0.113.12                             9f86d081884c7d65  8 days   expires 2026-06-25  VALID
WARNING: certificates differ across addresses
```

Addresses that are unreachable from the host (e.g. IPv6 on an IPv4-only machine) are reported as `skipped` and do not count as failures, so `-all-ips` stays clean on single-stack hosts without any flag. Use `-4` / `-6` to restrict the check to one family explicitly.

In JSON mode the result is `{ "domain", "certificates_match", "addresses": [...] }`, where each address is the usual certificate object plus `ip` and `fingerprint` (a skipped address is `{ "ip", "skipped": true, "error" }`, and a real failure `{ "ip", "error" }`). Exit code: `1` if nothing was reachable or an address failed for a real reason, otherwise `2` if the certificates differ or any expires within `-threshold`, otherwise `0`.

### Prometheus output (`-output prometheus`)

Emits metrics in the Prometheus exposition format — one set per domain (single or batch) — for scraping via the node_exporter [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector) or alerting:

```text
# HELP ssl_cert_expiry_days Days until the leaf certificate expires.
# TYPE ssl_cert_expiry_days gauge
ssl_cert_expiry_days{domain="example.com"} 80
ssl_cert_min_expiry_days{domain="example.com"} 80
ssl_cert_not_after_timestamp{domain="example.com"} 1757432803
ssl_cert_chain_valid{domain="example.com"} 1
```

`ssl_cert_up{domain}` is `0` for a domain that could not be retrieved (and no other samples are emitted for it), so you can alert on scrape failures separately from expiry. `ssl_cert_pin_match` is added when `-pin` is set. Typical cron usage writes to the collector directory:

```bash
ssl-watch -domain a.com,b.com -output prometheus > /var/lib/node_exporter/ssl_watch.prom
```

</details>

<details>
<summary><strong>Exit codes</strong></summary>

- `0` — success (and, with `-threshold`, days remaining is at or above the threshold for every certificate in the chain).
- `3` — an explicit expectation failed: `-pin` did not match, or `-expect-issuer` did not match. Takes precedence over `2`.
- `2` — a certificate expires within `-threshold` days, or `-strict` is set and a warning fired.
- `1` — an error occurred (connection failure, parse error, invalid arguments).

When several domains are checked, the codes are aggregated: `1` if any domain failed to be retrieved, otherwise `2` if any certificate expires within `-threshold`, otherwise `0`.

</details>

## License

[MIT](LICENSE)
