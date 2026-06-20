# Contributing to ssl-watch

Thanks for your interest in improving ssl-watch! This is a small, focused
command-line tool, so contributions that keep it simple and dependency-light are
especially welcome.

## Development setup

Go is **not required locally** — the build, tests and linter all run inside
containers via the Makefile, so all you need is Docker.

| Command | What it does |
| --- | --- |
| `make test-docker` | `go vet` + `go test ./...` in the Go container |
| `make build-docker` | build the binary into `./bin` in the Go container |
| `make lint-docker` | run `golangci-lint` in its container |

The container images are pinned and overridable:

```bash
make test-docker GO_IMAGE=golang:1.23
make lint-docker LINT_IMAGE=golangci/golangci-lint:v2.12.2
```

If you do have a local Go toolchain (1.23+), the plain targets also work:
`make test`, `make build`, `make format`.

## Before opening a pull request

- `make test-docker` is green (vet + tests).
- `make lint-docker` reports `0 issues`.
- New behavior is covered by tests. Avoid placeholder tests that always pass.
- Keep changes minimal and on-topic — no unrelated refactors or reformatting.

## Commit messages

Use short, imperative messages prefixed with a type:

```
fix: omit redundant used_ip in -all-ips JSON
feat: add -all-ips to check every resolved address
docs: clarify -threshold exit codes
```

Common types: `fix`, `feat`, `refactor`, `docs`, `chore`. Branch off `master`
and open the PR against `master`.

## Project layout

| Path | Responsibility |
| --- | --- |
| `main.go` | CLI entry point, flag validation, single/batch/`-all-ips` routing |
| `internal/cert` | fetching certificates (TLS/STARTTLS), inspection and text/JSON printing |
| `internal/flags` | flag definitions, parsing and the `-help` usage text |
| `internal/validation` | input validation helpers |

## Reporting issues

When filing a bug, include the exact command, the output you got, the output you
expected, and the ssl-watch version (`ssl-watch -version`).
