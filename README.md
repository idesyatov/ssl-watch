# SSLWatch

SSLWatch is a simple command-line tool to check the SSL certificate of a domain or a local certificate file. It retrieves and displays information about the SSL certificate, including the subject, issuer, expiration date, and the number of days remaining until expiration.

## Usage

To use SSLWatch, you need to specify either the domain you want to check or the path to a local certificate file. You can also optionally specify a port and an IP address. Additionally, you can use the `-short` flag to output only the number of days remaining until the certificate expires.

### Command Line Arguments

- `-domain <domain>`: The domain to check (required if `-certfile` is not specified).
- `-certfile <path>`: The path to the local certificate file (required if `-domain` is not specified).
- `-port <port>`: The port to connect to (default is 443).
- `-ipaddr <ipaddr>`: The IP address to connect to (optional).
- `-short`: Output only the number of days remaining until certificate expiration (optional).

### Examples

```bash
# Check the SSL certificate for a domain
go run main.go -domain example.com

# Check a local certificate file
go run main.go -certfile /path/to/certificate.crt

# Check a domain with a specific port
go run main.go -domain example.com -port 8443

# Check a domain using a specific IP address
go run main.go -domain example.com -ipaddr 192.0.2.1

# Check a domain and output only the number of days remaining until expiration
go run main.go -domain example.com -short

# Check a local certificate file and output only the number of days remaining until expiration
go run main.go -certfile /path/to/certificate.crt -short

# Check a domain with a specific port and IP address
go run main.go -domain example.com -port 8443 -ipaddr 192.0.2.1
```

## Installation

You can install SSLWatch using the following command:

```bash
go install github.com/idesyatov/SSLWatch@latest
```