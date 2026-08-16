// Package tools implements the signet-mcp tool handlers, grouped in
// toolsets that can be enabled or disabled via configuration.
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"

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
	cimdHTTP := &http.Client{
		Timeout: cfg.HTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if !cfg.CIMDAllowPrivate {
		// SSRF guard, mirroring Signet's own CIMD fetcher: refuse
		// connections to loopback, private, and link-local addresses so
		// signet_validate_cimd cannot probe the server's network. The check
		// runs at dial time on the resolved IP, so DNS tricks cannot
		// bypass it. Opt out with --cimd-allow-private-networks.
		cimdHTTP.Transport = &http.Transport{
			DialContext: (&net.Dialer{Control: refusePrivateAddr}).DialContext,
		}
	}
	d := &Deps{API: api, Cfg: cfg, Log: log, cimdHTTP: cimdHTTP}
	// Lazy verifier construction: discovery is bounded by the configured
	// HTTP timeout, and only a successful verifier is cached so a transient
	// discovery failure does not poison every later signet_decode_jwt call.
	var (
		mu     sync.Mutex
		cached *jwksauth.Verifier
	)
	d.verifier = func() (*jwksauth.Verifier, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached != nil {
			return cached, nil
		}
		// Audience is checked per-tool (callers debug tokens minted for
		// arbitrary resources), so skip it here.
		v, err := jwksauth.NewVerifierSkipAudience(context.Background(), cfg.Issuer,
			jwksauth.WithDiscoveryTimeout(cfg.HTTPTimeout))
		if err != nil {
			return nil, err
		}
		cached = v
		return v, nil
	}
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

// refusePrivateAddr is a net.Dialer Control hook that rejects any resolved
// address that is not public unicast: loopback, RFC 1918/ULA private,
// link-local (including 169.254.169.254-style metadata endpoints),
// multicast, and unspecified addresses are all refused.
func refusePrivateAddr(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("cannot parse dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("cannot parse dial IP %q: %w", host, err)
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("refusing to connect to non-public address %s "+
			"(start signet-mcp with --cimd-allow-private-networks to allow this)", ip)
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
