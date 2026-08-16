// Package tools implements the signet-mcp tool handlers, grouped in
// toolsets that can be enabled or disabled via configuration.
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/go-signet/sdk-go/jwksauth"

	"github.com/go-signet/signet-mcp/internal/config"
	"github.com/go-signet/signet-mcp/internal/signetapi"
)

// Deps carries the shared dependencies every tool handler needs.
type Deps struct {
	API *signetapi.Client
	Cfg *config.Config
	Log *slog.Logger

	// verifier lazily builds the offline JWT verifier used by
	// signet_decode_jwt. Construction performs OIDC discovery, so it is
	// deferred until the first call and cached.
	verifier func() (*jwksauth.Verifier, error)

	// cimdHTTP fetches CIMD documents: bounded timeout, no redirects.
	cimdHTTP *http.Client
}

// NewDeps wires up a Deps for the given configuration.
func NewDeps(api *signetapi.Client, cfg *config.Config, log *slog.Logger) *Deps {
	d := &Deps{
		API: api, Cfg: cfg, Log: log,
		cimdHTTP: &http.Client{
			Timeout: cfg.HTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	d.verifier = sync.OnceValues(func() (*jwksauth.Verifier, error) {
		// Audience is checked per-tool (callers debug tokens minted for
		// arbitrary resources), so skip it here.
		return jwksauth.NewVerifierSkipAudience(context.Background(), cfg.Issuer)
	})
	return d
}

// clientCreds resolves per-call client credentials, falling back to the
// configured defaults. The configured secret is only used together with the
// configured client_id, never mixed with a caller-supplied one.
func (d *Deps) clientCreds(id, secret string) (string, string) {
	if id == "" {
		return d.Cfg.ClientID, d.Cfg.ClientSecret
	}
	return id, secret
}

// Register adds all enabled toolsets to the server.
func Register(server *mcp.Server, d *Deps) error {
	for _, ts := range d.Cfg.Toolsets {
		switch ts {
		case config.ToolsetDiagnostics:
			registerDiagnostics(server, d)
		case config.ToolsetFlow:
			registerFlow(server, d)
		default:
			return fmt.Errorf("unknown toolset %q", ts)
		}
	}
	return nil
}

// boolPtr is a convenience for ToolAnnotations pointer fields.
func boolPtr(b bool) *bool { return &b }

// readOnly marks a tool that never modifies server state.
func readOnly(title string) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true}
}

// write marks a non-destructive write tool.
func write(title string, idempotent bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		Title:           title,
		DestructiveHint: boolPtr(false),
		IdempotentHint:  idempotent,
	}
}
