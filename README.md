# signet-mcp

[![Lint and Testing](https://github.com/go-signet/signet-mcp/actions/workflows/testing.yml/badge.svg)](https://github.com/go-signet/signet-mcp/actions/workflows/testing.yml)
[![CodeQL](https://github.com/go-signet/signet-mcp/actions/workflows/codeql.yml/badge.svg)](https://github.com/go-signet/signet-mcp/actions/workflows/codeql.yml)
[![Trivy Security Scan](https://github.com/go-signet/signet-mcp/actions/workflows/security.yml/badge.svg)](https://github.com/go-signet/signet-mcp/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/go-signet/signet-mcp/branch/main/graph/badge.svg)](https://codecov.io/gh/go-signet/signet-mcp)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-signet/signet-mcp.svg)](https://pkg.go.dev/github.com/go-signet/signet-mcp)
[![GitHub release](https://img.shields.io/github/v/release/go-signet/signet-mcp?include_prereleases)](https://github.com/go-signet/signet-mcp/releases)

The official [MCP](https://modelcontextprotocol.io) server for
[Signet](https://github.com/go-signet/signet), the OAuth 2.0 / OIDC
authorization server. It lets AI assistants (Claude Code, IDEs, chat
clients) inspect and debug a Signet deployment directly: discovery
metadata, JWT diagnostics, token introspection and revocation, and live
testing of all four OAuth flows.

signet-mcp is stateless — it persists nothing; tokens only ever exist in
memory for the duration of a tool call.

## Tools (v1)

Tools are grouped in **toolsets** that can be enabled per session with
`--toolsets` (default: both).

### `diagnostics`

| Tool                      | Description                                                           |
| ------------------------- | --------------------------------------------------------------------- |
| `signet_get_metadata`     | Fetch RFC 8414 + OIDC discovery documents and diff them               |
| `signet_get_jwks`         | List JWKS public keys (kid / kty / alg / use / crv)                   |
| `signet_health`           | Server health, dependency probes, feature flags                       |
| `signet_decode_jwt`       | **Offline** JWT decode + JWKS signature check, per-claim explanations |
| `signet_tokeninfo`        | Online access-token validation (`GET /oauth/tokeninfo`)               |
| `signet_introspect_token` | RFC 7662 introspection (needs client credentials)                     |
| `signet_userinfo`         | OIDC UserInfo claims for an access token                              |
| `signet_validate_cimd`    | Fetch + validate a Client ID Metadata Document (MCP 2026-07-28)       |
| `signet_revoke_token`     | RFC 7009 revocation                                                   |

### `flow`

| Tool                              | Description                                                               |
| --------------------------------- | ------------------------------------------------------------------------- |
| `signet_device_flow_start`        | Start an RFC 8628 device flow (supports RFC 8707 `resource`)              |
| `signet_device_flow_poll`         | Poll for the device-flow token, interpreting `authorization_pending` etc. |
| `signet_build_authorize_url`      | Local PKCE (S256) generation + `/oauth/authorize` URL builder             |
| `signet_exchange_code`            | Exchange an authorization code, verifying RFC 9207 `iss`                  |
| `signet_client_credentials_token` | Obtain an M2M token and check audience binding                            |
| `signet_refresh_token`            | Refresh a token, observing rotation and RFC 8707 §2.2 audience narrowing  |

Destructive or state-changing tools carry the corresponding MCP
annotations (`readOnlyHint` / `destructiveHint` / `idempotentHint`) so
clients can gate confirmation.

## Install

```bash
go install github.com/go-signet/signet-mcp@latest
```

Or grab a release binary from the releases page.

## Usage

### stdio (local)

```bash
signet-mcp --issuer https://auth.example.com \
  --client-id my-client --client-secret my-secret   # optional defaults for tools that need client credentials
```

#### Claude Code

```bash
claude mcp add signet -- signet-mcp --issuer https://auth.example.com --client-id my-client
```

Or in `.mcp.json`:

```json
{
  "mcpServers": {
    "signet": {
      "command": "signet-mcp",
      "args": [
        "--issuer",
        "https://auth.example.com",
        "--client-id",
        "my-client"
      ]
    }
  }
}
```

### Streamable HTTP (remote, OAuth-protected)

In HTTP mode signet-mcp dogfoods Signet: it acts as an OAuth resource
server protected by the very Signet it serves tools for. Bearer tokens
are verified offline against Signet's JWKS, must be access tokens
(`type == "access"`), and must carry this server's public URL in their
audience (RFC 8707). RFC 9728 protected-resource metadata is served at
`/.well-known/oauth-protected-resource`, and `401` responses point to it
so MCP clients can discover the authorization server automatically.

```bash
signet-mcp --issuer https://auth.example.com \
  --transport http --addr :8090 \
  --public-url https://mcp.example.com
```

Clients then obtain tokens with `resource=https://mcp.example.com`.

#### claude.ai / Claude Code (remote)

Add a custom connector with URL `https://mcp.example.com` — the OAuth
flow is discovered from the protected-resource metadata. From Claude
Code:

```bash
claude mcp add --transport http signet https://mcp.example.com
```

### Configuration

| Flag                 | Env                        | Default            |                                                   |
| -------------------- | -------------------------- | ------------------ | ------------------------------------------------- |
| `--issuer`           | `SIGNET_MCP_ISSUER`        | —                  | Signet issuer URL (required)                      |
| `--transport`        | `SIGNET_MCP_TRANSPORT`     | `stdio`            | `stdio` or `http`                                 |
| `--addr`             | `SIGNET_MCP_ADDR`          | `localhost:8090`   | HTTP listen address                               |
| `--public-url`       | `SIGNET_MCP_PUBLIC_URL`    | `http://<addr>`    | External base URL = RFC 8707 resource identifier  |
| `--toolsets`         | `SIGNET_MCP_TOOLSETS`      | `diagnostics,flow` | Enabled toolsets                                  |
| `--client-id`        | `SIGNET_MCP_CLIENT_ID`     | —                  | Default OAuth client for flow tools               |
| `--client-secret`    | `SIGNET_MCP_CLIENT_SECRET` | —                  | Default client secret                             |
| `--http-timeout`     | —                          | `15s`              | Outbound request timeout                          |
| `--shutdown-timeout` | —                          | `30s`              | Graceful shutdown window                          |
| `--log-level`        | `SIGNET_MCP_LOG_LEVEL`     | `info`             | `debug`/`info`/`warn`/`error` (logs go to stderr) |
| `--log-json`         | —                          | `false`            | JSON log output                                   |

Shutdown is graceful: SIGINT/SIGTERM drains in-flight tool calls and the
HTTP listener within `--shutdown-timeout`.

## Example session

> **You:** why is my device flow failing against staging?
>
> **Claude:** _calls `signet_get_metadata`, `signet_health`,
> `signet_device_flow_start`_ — your client isn't allowed the
> device_code grant; the token endpoint returned `unauthorized_client`…

## Development

```bash
make build   # bin/signet-mcp
make test    # unit tests
make lint    # golangci-lint v2
make fmt     # gofmt + gofumpt + golines
```

## v2 backlog

Account self-service (`account`) and admin (`admin`) toolsets are
planned for v2 — they depend on Signet growing Bearer-authenticated
JSON APIs (`/api/v1/me/*`, `/api/v1/admin/*`). MCP Resources and
Prompts are also deferred to v2.

## License

MIT
