# SSLWatch

SSLWatch is a simple command-line tool to check the SSL certificate of a domain. It retrieves and displays information about the SSL certificate, including the subject, issuer, expiration date, and the number of days remaining until expiration.

## Usage

To use SSLWatch, you need to specify the domain you want to check. You can also optionally specify a port and an IP address. Additionally, you can use the `-short` flag to output only the number of days remaining until the certificate expires.

### Command Line Arguments

- `-domain <domain>`: The domain to check (required).
- `-port <port>`: The port to connect to (default is 443).
- `-ipaddr <ipaddr>`: The IP address to connect to (optional).
- `-short`: Output only the number of days remaining until certificate expiration (optional).

### Example

To check the SSL certificate for a domain:

```bash
go run main.go -domain example.com