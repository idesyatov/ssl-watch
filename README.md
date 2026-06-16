# ssl-watch

ssl-watch is a simple command-line tool to check the SSL certificate of a domain or a local certificate file. It retrieves and displays information about the SSL certificate, including the subject, issuer, expiration date, and the number of days remaining until expiration.

## Usage

To use ssl-watch, you need to specify either the domain you want to check or the path to a local certificate file. You can also optionally specify a port and an IP address. Additionally, you can use the `-short` flag to output only the number of days remaining until the certificate expires.

### Command Line Arguments

- `-domain <domain>`: The domain to check (required if `-certfile` is not specified).
- `-certfile <path>`: The path to the local certificate file (required if `-domain` is not specified).
- `-port <port>`: The port to connect to (default is 443).
- `-ipaddr <ipaddr>`: The IP address to connect to (optional).
- `-short`: Output only the number of days remaining until certificate expiration (optional).

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
```

## Installation

### Pre-built binaries

Download an archive for your OS/arch from the [latest release](https://github.com/idesyatov/ssl-watch/releases/latest), extract it and place the binary somewhere on your `PATH`.

Available builds:

- `linux_amd64`, `linux_arm64`
- `darwin_amd64` (Intel Mac), `darwin_arm64` (Apple Silicon)
- `windows_amd64`

Example (Linux amd64):

```bash
VERSION=1.0.7
curl -L -o ssl-watch.tar.gz \
  https://github.com/idesyatov/ssl-watch/releases/download/v$VERSION/ssl-watch_${VERSION}_linux_amd64.tar.gz
tar -xzf ssl-watch.tar.gz ssl-watch
sudo install -m 0755 ssl-watch /usr/local/bin/
ssl-watch -version
```

Example (macOS, Apple Silicon):

```bash
VERSION=1.0.7
curl -L -o ssl-watch.tar.gz \
  https://github.com/idesyatov/ssl-watch/releases/download/v$VERSION/ssl-watch_${VERSION}_darwin_arm64.tar.gz
tar -xzf ssl-watch.tar.gz ssl-watch
sudo install -m 0755 ssl-watch /usr/local/bin/
ssl-watch -version
```

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