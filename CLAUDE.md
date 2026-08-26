# CLAUDE.md — headscale-ops

headscale-ops is a workstation-only Go CLI for a narrow Headscale v0.29.3 REST administration subset.

## Locked scope

- No daemon, web UI, container, or remote service.
- No Headscale policy editor or direct node registration.
- No integration into Velociportal; Velociportal remains read-only and visibility-only.
- HTTPS only. Never add an insecure TLS mode, redirect following, or environment-proxy support for credentialed calls.
- Rely on the workstation system trust store; do not store CA private keys.
- Treat Headscale API keys as unscoped administrator credentials.
- Keep credential files owner-only and atomic.
- Omit key secrets from list output; new secrets may appear only once on stdout.
- Require explicit `--yes` for destructive operations.
- Match Headscale v0.29.3 paths and JSON shapes from the tagged OpenAPI specification.
- Standard library first; `golang.org/x/term` is used only for hidden input.
- Run `go test -race -count=1 ./...` and `go vet ./...` for changes.
- Never add AI attribution to commits.
