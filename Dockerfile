# Minimal runtime image for the ssl-watch CLI.
#
# The release binary is statically linked (CGO disabled), so it needs no libc and
# runs on `scratch`. The one thing it does need from a base system is a CA bundle:
# ssl-watch verifies certificate chains against the public roots, and without
# /etc/ssl/certs/ca-certificates.crt every chain would show as INVALID. We copy
# the bundle from an Alpine stage so the final image stays tiny (just the binary
# plus the CA bundle).
#
# GoReleaser supplies the prebuilt `ssl-watch` binary in the build context; for a
# local image build, produce it first (see CONTRIBUTING.md / the README Docker section).
FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ssl-watch /ssl-watch
ENTRYPOINT ["/ssl-watch"]
