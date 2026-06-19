# ssl-watch

ssl-watch is a simple command-line tool to check the SSL certificate of a domain (or several at once) or a local certificate file. It retrieves and displays information about the SSL certificate, including the subject, issuer, SANs, serial number, signature algorithm, validity period, the number of days remaining until expiration, and — for fetched certificates — the verification status of the certificate chain. It can also reach certificates behind STARTTLS (SMTP/IMAP/POP3/FTP).

## Usage

To use ssl-watch, you need to specify either the domain(s) you want to check (via `-domain` or `-domain-file`) or the path to a local certificate file. You can also optionally specify a port and an IP address. Additionally, you can use the `-short` flag to output only the number of days remaining until the certificate expires.

Several domains can be checked in one run via a comma-separated `-domain` or a `-domain-file`. In text mode each domain is printed as its own block prefixed with `==> <domain>`; in JSON mode the output becomes an array of objects (one per domain, each tagged with `domain`, and an `{ "domain", "error" }` entry for any that could not be retrieved).

By default the certificate chain of a fetched certificate is verified against the system root store (trust, hostname and validity period). The result is reported as `Chain: VALID` or `Chain: INVALID (reason)`. Use `-insecure` to skip this check (e.g. for self-signed certificates). Chain verification is not performed for certificates loaded from a file.

The whole chain is also checked for expiry: if an intermediate certificate expires *before* the leaf, a `WARNING: intermediate "..." expires in N days, before the leaf` line is printed (and a `chain_expiry_warning` object is added to the JSON output). With `-threshold`, the exit code is driven by the weakest link in the chain, not the leaf alone.

For monitoring (cron/CI), use `-threshold` to make the tool exit with code `2` when the certificate is close to expiry (see [Exit codes](#exit-codes)), and `-output json` for machine-readable output.

### Command Line Arguments

- `-domain <domains>`: The domain to check, or several comma-separated (e.g. `a.com,b.com`). Required if `-certfile`/`-domain-file` are not specified.
- `-domain-file <path>`: Read domains from a file, one per line (`-` reads stdin). Blank lines and lines starting with `#` are ignored.
- `-certfile <path>`: The path to the local certificate file (required if `-domain` is not specified).
- `-port <port>`: The port to connect to (default is 443; with `-starttls` the protocol's default port is used unless overridden).
- `-ipaddr <ipaddr>`: The IP address to connect to (optional; only valid with a single domain).
- `-starttls <proto>`: Upgrade the connection via STARTTLS before reading the certificate. One of `smtp`, `imap`, `pop3`, `ftp` (default: direct TLS).
- `-short`: Output only the number of days remaining until certificate expiration (optional).
- `-insecure`: Skip certificate chain verification (optional).
- `-threshold <days>`: Exit with code `2` when the days remaining is below this value; `0` disables (optional).
- `-output <text|json>`: Output format (default `text`).
- `-timeout <seconds>`: Connection timeout when fetching a remote certificate (default `10`).

In text mode, when writing to an interactive terminal, the days-remaining value and the chain status are colorized (red/yellow/green). Color is disabled automatically when output is piped/redirected or when the `NO_COLOR` environment variable is set.

### Examples

```bash
# Check the SSL certificate for a domain
ssl-watch -domain example.com

# Check a local certificate file
ssl-watch -certfile /path/to/certificate.crt

# Check a domain with a specific port
ssl-watch -domain example.com -port 8443

# Check a domain using a specific IP address
ssl-watch -domain example.com -ipaddr 192.0.2.1

# Check a domain and output only the number of days remaining until expiration
ssl-watch -domain example.com -short

# Check a local certificate file and output only the number of days remaining until expiration
ssl-watch -certfile /path/to/certificate.crt -short

# Check a domain with a specific port and IP address
ssl-watch -domain example.com -port 8443 -ipaddr 192.0.2.1

# Check a domain with a self-signed certificate, skipping chain verification
ssl-watch -domain self-signed.example.com -insecure

# Monitoring: exit code 2 if the certificate expires within 30 days
ssl-watch -domain example.com -threshold 30 -short

# Machine-readable JSON output
ssl-watch -domain example.com -output json

# Use a shorter connection timeout (3 seconds)
ssl-watch -domain example.com -timeout 3

# Check several domains at once
ssl-watch -domain a.com,b.com,c.com

# Check a list of domains from a file (one per line)
ssl-watch -domain-file domains.txt -threshold 30

# Read the domain list from stdin
cat domains.txt | ssl-watch -domain-file -

# Check a mail server certificate via STARTTLS (defaults to port 587)
ssl-watch -domain smtp.example.com -starttls smtp
```

### Sample output

```text
Certificate for github.com
Subject: CN=github.com
Issuer: CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB
SANs: github.com, www.github.com
Serial: E7:CE:CC:3B:13:FB:3B:7B:8A:46:EA:8C:D0:AE:B7:1C
Signature: ECDSA-SHA256
Valid from: 2026-05-05 00:00:00 +0000 UTC
Expires on: 2026-08-02 23:59:59 +0000 UTC
Days remaining: 45
Used IP address: 140.82.121.4
Chain: VALID
```

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
  "not_before": "2026-05-05T00:00:00Z",
  "not_after": "2026-08-02T23:59:59Z",
  "days_remaining": 45,
  "used_ip": "140.82.121.4",
  "chain_valid": true
}
```

The `chain_valid` and `chain_error` fields are omitted for certificates loaded from a file and when `-insecure` is used. The `chain_expiry_warning` object (`{"subject": ..., "days_remaining": ...}`) is present only when an intermediate certificate expires before the leaf.

When several domains are checked, the JSON output is an array; each element carries an extra `domain` field, and domains that could not be retrieved appear as `{"domain": "...", "error": "..."}`.

### Exit codes

- `0`: success — certificate retrieved (and, with `-threshold`, days remaining is at or above the threshold for every certificate in the chain).
- `2`: a certificate in the chain (leaf or an intermediate) expires within `-threshold` days.
- `1`: an error occurred (connection failure, parse error, invalid arguments).

When several domains are checked, the codes are aggregated: `1` if any domain failed to be retrieved, otherwise `2` if any certificate expires within `-threshold`, otherwise `0`.

## Installation

### Install script (Linux & macOS)

The fastest way — one command that detects your OS, architecture and the latest
release automatically, verifies the archive's SHA-256 checksum, then installs the
binary to `/usr/local/bin`:

```bash
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | sh
```

`sudo` is requested only if the install directory is not writable. You can override
the target directory or pin a version with environment variables:

```bash
# Install to a custom directory (no sudo needed)
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | BINDIR="$HOME/.local/bin" sh

# Install a specific version
curl -fsSL https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh | VERSION=v1.2.0 sh
```

> Prefer to review before running? Download [`install.sh`](https://raw.githubusercontent.com/idesyatov/ssl-watch/master/install.sh), read it, then run `sh install.sh`.

### Pre-built binaries (manual)

Alternatively, download an archive for your OS/arch from the [latest release](https://github.com/idesyatov/ssl-watch/releases/latest), extract it and place the binary somewhere on your `PATH`.

Available builds:

- `linux_amd64`, `linux_arm64`
- `darwin_amd64` (Intel Mac), `darwin_arm64` (Apple Silicon)
- `windows_amd64` (`.zip` archive)

SHA-256 checksums for all archives are published as `checksums.txt` on the same release page.

### From source

Using Go:

```bash
go install github.com/idesyatov/ssl-watch@latest
```

Or clone and build manually:

```bash
git clone https://github.com/idesyatov/ssl-watch.git
cd ssl-watch
make build
```