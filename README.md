# headscale-ops

`headscale-ops` is a small workstation-only CLI for administering Headscale v0.29.3 over its HTTPS REST API. It replaces routine TrueNAS shell and `docker exec` work after the one unavoidable first-key bootstrap.

It is deliberately **not** a daemon, container, dashboard, policy editor, authentication service, or complete Headscale client library.

## Security model

- HTTPS is mandatory; HTTP configuration is rejected.
- Certificate verification uses the workstation's normal system trust store.
- There is no `--insecure` mode and no application-specific CA bypass.
- The HTTP client ignores `HTTP_PROXY`/`HTTPS_PROXY`, refuses redirects, requires TLS 1.2 or newer, and bounds headers and bodies.
- The API key is stored in an atomic owner-only JSON file under the user config directory.
- API keys in Headscale v0.29.3 are unscoped administrator credentials.
- Destructive operations require an explicit `--yes` flag.
- Pre-auth-key and API-key list output omits secret material.
- New key secrets are written once to stdout; diagnostics go to stderr so the secret can be redirected to an owner-only destination.

The canonical Velociportal deployment uses the existing NPM-managed Headscale HTTPS origin with split-horizon/private DNS and a publicly trusted DNS-01 wildcard certificate. Direct native Headscale HTTPS with a private CA remains optional; when selected, protect the CA private key separately and install only its public root in the workstation trust store.

## Supported operations

| Area | Commands |
|---|---|
| Connectivity | `status` |
| Tool provenance | `version` |
| Users | `list`, `create`, `rename`, `delete` |
| Nodes | `list`, `rename`, `expire`/disable expiry, `delete`, `set-tags` |
| Pre-auth keys | `list`, `create`, `expire` |
| API keys | `list`, `create`, `expire` |

The command paths and JSON shapes are pinned to Headscale's [v0.29.3 generated OpenAPI specification](https://github.com/juanfont/headscale/blob/v0.29.3/gen/openapiv2/headscale/v1/headscale.swagger.json). `status` verifies the public `/version` result is an unmodified v0.29.3 build, then reports health, database connectivity, build provenance, and verified TLS certificate details. The separate `version` command reports this CLI's build provenance.

## Install a verified release

> [!NOTE]
> These commands apply only after the named release exists at [github.com/cybersader/headscale-ops](https://github.com/cybersader/headscale-ops/releases). Preparing the workflow does not publish a binary.

Choose an immutable version and the architecture matching the Fedora workstation:

```bash
VERSION=v0.1.0
```

```bash
ARCH=amd64
```

Use `ARCH=arm64` on an ARM64/aarch64 workstation. Download into a temporary directory:

```bash
RELEASE_DIR="$(mktemp -d)"
```

```bash
ASSET="headscale-ops_${VERSION#v}_linux_${ARCH}"
```

```bash
curl --fail --location --output "$RELEASE_DIR/$ASSET" "https://github.com/cybersader/headscale-ops/releases/download/$VERSION/$ASSET"
```

```bash
curl --fail --location --output "$RELEASE_DIR/SHA256SUMS" "https://github.com/cybersader/headscale-ops/releases/download/$VERSION/SHA256SUMS"
```

Verify the selected binary against the release checksum before installing it:

```bash
(cd "$RELEASE_DIR" && awk -v asset="$ASSET" '$2 == asset { print }' SHA256SUMS >selected.sha256 && test "$(wc -l <selected.sha256)" -eq 1 && sha256sum --check --strict selected.sha256)
```

The command must report `OK`. Also require GitHub's **Immutable** lock on the release page. When an authenticated GitHub CLI is available, verify the release attestation and the local asset directly:

```bash
gh release verify "$VERSION" --repo cybersader/headscale-ops
```

```bash
gh release verify-asset "$VERSION" "$RELEASE_DIR/$ASSET" --repo cybersader/headscale-ops
```

Do not install if the release is not immutable or either verification fails. Then install it owner-controlled under `~/.local/bin`:

```bash
install -D -m 0755 "$RELEASE_DIR/$ASSET" "$HOME/.local/bin/headscale-ops"
```

Confirm the command resolves from the expected location and reports the selected version:

```bash
command -v headscale-ops
```

```bash
headscale-ops version
```

If `~/.local/bin` is not on `PATH`, add it through the workstation's normal shell-profile management before continuing. Remove the temporary files after installation:

```bash
rm -rf -- "$RELEASE_DIR"
```

The release workflow builds static Linux AMD64 and ARM64 binaries from the selected Git tag, binds that tag to the verified revision, embeds both values, generates SHA-256 checksums, and compares every draft asset with GitHub's server-reported digest before publication. It requires the operator to confirm repository release immutability is enabled and verifies the published release attestation. If publication does not become immutable, an exit trap attempts to remove the mutable release; any API ambiguity is reported for manual inspection rather than claimed as successful cleanup.

Maintainers must enable **Settings → Releases → Enable release immutability** before dispatching the workflow with publication enabled. Matching partial drafts and already-published matching immutable releases can resume verification. A matching mutable release is removed and recreated under the confirmed policy; conflicting or extra assets fail closed and require manual review.

## Build from source

Until a public release exists—or when deliberately auditing current source—use Go 1.22 or newer from a trusted checkout:

```bash
make check
```

```bash
make install
```

The default install path is `~/.local/bin/headscale-ops`. A source build reports `dev` unless `VERSION` and `REVISION` are supplied explicitly.

## Upgrade and uninstall

To upgrade, repeat the checksum-verified release installation with a newer immutable `VERSION`. The final `install` command replaces the executable only after the new download has passed checksum verification. Run `headscale-ops version` afterward.

Remove only the installed executable to uninstall the CLI:

```bash
rm -f "$HOME/.local/bin/headscale-ops"
```

Uninstalling the binary does not remove the owner-only configuration or its unscoped administrative API key. On Fedora, the default is `${XDG_CONFIG_HOME:-$HOME/.config}/headscale-ops/config.json`; `HEADSCALE_OPS_CONFIG` or a command-level `--config FILE` may place it elsewhere. Review the path actually used during configuration and any backups explicitly before deleting them.

## One-time configuration

Before configuring the CLI on the canonical deployment path:

1. Configure the existing NPM Headscale proxy with WebSocket/upgrade preservation and the operator's already trusted certificate lifecycle.
2. Use split-horizon/private DNS for the Headscale hostname; do not publish its address in public DNS. Prefer an existing DNS-01 wildcard certificate so the exact hostname is not disclosed through certificate-transparency logs.
3. Verify `https://headscale.example.net/health` from the workstation without an insecure flag.
4. Perform the one local Headscale API-key bootstrap with a short expiry.

Then run:

```bash
headscale-ops configure --server-url https://headscale.example.net
```

Direct native Headscale HTTPS with a private CA is an optional alternative. If selected, install only the public root in Fedora's system trust store and require the same verification checks; `headscale-ops` never disables TLS verification.

Paste the API key at the hidden prompt. The default path follows the operating system user-config directory:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/headscale-ops/config.json
```

On a normal Fedora installation with `XDG_CONFIG_HOME` unset, this is `~/.config/headscale-ops/config.json`. The directory is mode `0700` and the file is mode `0600`. `HEADSCALE_OPS_CONFIG` or `--config FILE` overrides the path; record that custom location because uninstall guidance cannot infer a command-level override. An existing custom parent directory must already be owner-only, and the tool will not chmod a shared directory.

Verify the direct TLS and API path:

```bash
headscale-ops status
```

## Examples

### Users

```bash
headscale-ops user list
```

```bash
headscale-ops user create --name alice
```

```bash
headscale-ops user rename --id 7 --name alice@example.com
```

```bash
headscale-ops user delete --id 7 --yes
```

### Nodes

```bash
headscale-ops node list
```

```bash
headscale-ops node list --user alice
```

```bash
headscale-ops node rename --id 9 --name workstation
```

Expire immediately:

```bash
headscale-ops node expire --id 9 --yes
```

Remove expiry:

```bash
headscale-ops node expire --id 9 --disable --yes
```

Set forced tags:

```bash
headscale-ops node set-tags --id 9 --tag tag:server --tag tag:internal --yes
```

Assigning the first forced tag permanently converts a user-owned node into a tag-owned node in Headscale v0.29.3. All supplied tags must already exist in policy. The API rejects an empty tag list, so this CLI does not offer a tag-clearing operation.

```bash
headscale-ops node delete --id 9 --yes
```

### Pre-auth keys

List metadata without key secrets:

```bash
headscale-ops preauth list
```

Create a one-use key valid for one hour:

```bash
headscale-ops preauth create --user 7 --expiration 1h
```

Create a reusable tagged key and capture only the secret in an owner-only file:

```bash
umask 077; headscale-ops preauth create --user 7 --expiration 24h --reusable --tag tag:test >preauth.key
```

Expire it by numeric ID:

```bash
headscale-ops preauth expire --id 11 --yes
```

### API keys

List metadata without secrets:

```bash
headscale-ops apikey list
```

Create a replacement key and capture only the secret:

```bash
umask 077; headscale-ops apikey create --expiration 2160h >replacement-api.key
```

Expire by ID or prefix:

```bash
headscale-ops apikey expire --id 13 --yes
```

```bash
headscale-ops apikey expire --prefix hskey-api-AbCdEfGhIjKl --yes
```

## Output discipline

Server-provided table values are stripped of terminal control characters and bounded before display. Error excerpts are bounded and redact the configured API key. New key secrets are the only intentionally sensitive stdout output. If writing a newly created secret fails, the CLI makes a fresh bounded cleanup request to expire that credential and reports its non-secret ID or prefix if manual cleanup is still required.

Do not paste keys into command-line flags, chat, issue trackers, logs, or documentation. Prefer hidden input for the long-lived administration key and owner-only redirected files for one-time generated keys.

## Scope boundary

This CLI does not edit Headscale policy, register nodes directly, manage routes, expose a service, or belong inside Velociportal. Velociportal remains read-only and visibility-only.

## License

MIT
