// Package server assembles the MCP server, its transports, and — in HTTP
// mode — the OAuth resource-server protection (RFC 9728 PRM + RFC 8707
// audience-bound Bearer validation against the same Signet it serves tools
// for).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/go-signet/sdk-go/jwksauth"

	"github.com/go-signet/signet-mcp/internal/config"
	"github.com/go-signet/signet-mcp/internal/signetapi"
	"github.com/go-signet/signet-mcp/internal/tools"
)

// Version is stamped at build time via -ldflags.
var Version = "dev"

// Server bundles the MCP server with its configuration.
type Server struct {
	cfg *config.Config
	log *slog.Logger
	mcp *mcp.Server
}

// New builds the MCP server with all enabled toolsets registered.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	api, err := signetapi.New(cfg.Issuer, cfg.HTTPTimeout)
	if err != nil {
		return nil, err
	}
	deps := tools.NewDeps(api, cfg, log)

	m := mcp.NewServer(&mcp.Implementation{
		Name:    "signet-mcp",
		Title:   "Signet MCP",
		Version: Version,
	}, &mcp.ServerOptions{
		Instructions: "Tools for inspecting and debugging a Signet OAuth 2.0 authorization server at " +
			cfg.Issuer + ": discovery metadata, JWT diagnostics, token introspection/revocation, and " +
			"live testing of the device-code, authorization-code (PKCE), client-credentials and refresh flows.",
	})
	m.AddReceivingMiddleware(loggingMiddleware(log))
	if err := tools.Register(m, deps); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, log: log, mcp: m}, nil
}

// loggingMiddleware logs every tool call with name, duration and outcome.
func loggingMiddleware(log *slog.Logger) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			name := "?"
			if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
				name = p.Name
			}
			start := time.Now()
			res, err := next(ctx, method, req)
			outcome := "ok"
			switch {
			case err != nil:
				outcome = "protocol_error"
			default:
				if r, ok := res.(*mcp.CallToolResult); ok && r.IsError {
					outcome = "tool_error"
				}
			}
			log.Info("tool call",
				slog.String("tool", name),
				slog.Duration("duration", time.Since(start)),
				slog.String("outcome", outcome),
			)
			return res, err
		}
	}
}

// RunStdio serves a single MCP session on stdin/stdout until ctx is
// cancelled or the client disconnects.
func (s *Server) RunStdio(ctx context.Context) error {
	s.log.Info("serving MCP on stdio", slog.String("issuer", s.cfg.Issuer))
	err := s.mcp.Run(ctx, &mcp.StdioTransport{})
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// HTTPServer builds the streamable-HTTP server, protected as an OAuth
// resource server: Bearer tokens are verified offline against Signet's JWKS,
// must carry this server's resource identifier in aud (RFC 8707), and must
// be access tokens (type == "access"). RFC 9728 protected-resource metadata
// is served on the well-known path, and 401 responses point at it.
func (s *Server) HTTPServer(ctx context.Context) (*http.Server, error) {
	verifier, err := jwksauth.NewVerifier(ctx, s.cfg.Issuer, s.cfg.PublicURL)
	if err != nil {
		return nil, fmt.Errorf("building JWKS verifier for %s: %w", s.cfg.Issuer, err)
	}

	prmURL := s.cfg.PublicURL + "/.well-known/oauth-protected-resource"
	prm := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.cfg.PublicURL,
		AuthorizationServers:   []string{s.cfg.Issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "signet-mcp",
	})

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{Logger: s.log},
	)
	requireToken := auth.RequireBearerToken(
		bearerVerifier(verifier),
		&auth.RequireBearerTokenOptions{
			ResourceMetadataURL: prmURL,
		},
	)

	mux := http.NewServeMux()
	// Unauthenticated liveness probe for container orchestrators.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/.well-known/oauth-protected-resource", prm)
	mux.Handle("/.well-known/oauth-protected-resource/", prm)
	mux.Handle("/", requireToken(mcpHandler))

	s.log.Info("serving MCP over streamable HTTP",
		slog.String("addr", s.cfg.Addr),
		slog.String("resource", s.cfg.PublicURL),
		slog.String("issuer", s.cfg.Issuer),
	)
	return &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}, nil
}

// bearerVerifier adapts the sdk-go offline verifier to the MCP SDK's
// middleware contract, adding the Signet type == "access" check.
func bearerVerifier(v *jwksauth.Verifier) auth.TokenVerifier {
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		info, err := v.Verify(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		var tc struct {
			Type string `json:"type"`
		}
		if err := info.IDToken.Claims(&tc); err != nil {
			return nil, fmt.Errorf("%w: reading claims: %v", auth.ErrInvalidToken, err)
		}
		if tc.Type != "access" {
			return nil, fmt.Errorf(
				"%w: token type %q is not \"access\"",
				auth.ErrInvalidToken,
				tc.Type,
			)
		}
		return &auth.TokenInfo{
			Scopes:     info.Scopes,
			Expiration: info.Expiry,
			UserID:     info.Claims.UID,
		}, nil
	}
}
