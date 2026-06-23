# VHS tape for the README demo GIF.
# Render (Docker only), from the repo root, after building a static ./ssl-watch:
#   docker run --rm -v "$PWD:/vhs" -w /vhs \
#     -v "$PWD/ssl-watch:/usr/local/bin/ssl-watch" \
#     ghcr.io/charmbracelet/vhs demo/demo.tape

Output demo/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1180
Set Height 760
Set Padding 18
Set Theme "Dracula"
Set WindowBar Colorful
Set TypingSpeed 40ms

# Clean, minimal prompt; work in /tmp so the export demo writes inside the
# container (not the repo). None of this setup is shown in the GIF.
Hide
Type "cd /tmp && export PS1='$ ' TERM=xterm-256color" Enter
Type "clear" Enter
Show

# 1. A healthy certificate — full inspection, chain VALID (green in a TTY).
Type "ssl-watch -domain github.com" Sleep 500ms Enter
Sleep 3s
Hide Type "clear" Enter Show

# 2. The headline feature: where trust breaks — classified reason + issuer trail.
# Wait for the chain verdict to actually render (badssl can be slow) before the
# dwell, so the output is captured instead of being cut off by the next clear.
Type "ssl-watch -domain untrusted-root.badssl.com" Sleep 500ms Enter
Wait+Screen@20s /Chain:/
Sleep 3s
Hide Type "clear" Enter Show

# 3. The full certificate chain (leaf + intermediates).
Type "ssl-watch -domain github.com -chain" Sleep 500ms Enter
Sleep 3s
Hide Type "clear" Enter Show

# 4. Every IP of a domain — catch a balancer node serving a different certificate.
Type "ssl-watch -domain cloudflare.com -all-ips -4" Sleep 500ms Enter
Sleep 4s
Hide Type "clear" Enter Show

# 5. Fingerprints for pinning (certificate + public-key SPKI).
Type "ssl-watch -domain github.com -fingerprint" Sleep 500ms Enter
Sleep 3s
Hide Type "clear" Enter Show

# 6. Offline workflow: export the served chain to a file, then inspect it from disk.
Type "ssl-watch -domain github.com -export chain.pem" Sleep 400ms Enter
Sleep 1.5s
Type "ssl-watch -certfile chain.pem -chain" Sleep 400ms Enter
Sleep 3.5s
Hide Type "clear" Enter Show

# 7. Batch monitoring: several domains in parallel as a Nagios/Icinga plugin line.
Type "ssl-watch -domain github.com,cloudflare.com,expired.badssl.com -concurrency 3 -threshold 30 -output nagios" Sleep 500ms Enter
Sleep 6s
