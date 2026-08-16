// Package config holds the runtime configuration for signet-mcp.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Transport names accepted by --transport.
const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// Toolset names shipped in v1.
const (
	ToolsetDiagnostics = "diagnostics"
	ToolsetFlow        = "flow"
)

// DefaultToolsets are the toolsets enabled when --toolsets is not given.
var DefaultToolsets = []string{ToolsetDiagnostics, ToolsetFlow}

// Config is the resolved signet-mcp configuration.
type Config struct {
	// Issuer is the Signet issuer URL (required).
	Issuer string
	// Transport is "stdio" or "http".
	Transport string
	// Addr is the listen address for the HTTP transport.
	Addr string
	// PublicURL is the externally reachable base URL of this MCP server in
	// HTTP mode. It doubles as the RFC 8707 resource identifier that access
	// tokens must carry in their audience.
	PublicURL string
	// Toolsets lists the enabled toolsets.
	Toolsets []string
	// ClientID / ClientSecret are default OAuth client credentials used by
	// tools that need client authentication (introspect, revoke, flows) when
	// the tool call does not supply its own.
	ClientID     string
	ClientSecret string
	// CIMDAllowPrivate permits signet_validate_cimd to fetch documents from
	// loopback, private, and link-local addresses. Off by default so the
	// tool cannot be used as an SSRF proxy into the server's network,
	// mirroring Signet's CIMD_ALLOW_PRIVATE_NETWORKS.
	CIMDAllowPrivate bool
	// HTTPTimeout bounds each outbound request to Signet.
	HTTPTimeout time.Duration
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// LogJSON switches slog to JSON output.
	LogJSON bool
}

// envOr returns the environment variable value or a default.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// Parse builds a Config from command-line arguments and SIGNET_MCP_* env
// vars (flags win over env vars).
func Parse(args []string) (*Config, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("signet-mcp", flag.ContinueOnError)

	var toolsets string
	fs.StringVar(&cfg.Issuer, "issuer",
		envOr("SIGNET_MCP_ISSUER", ""),
		"Signet issuer URL, e.g. https://auth.example.com (env SIGNET_MCP_ISSUER)")
	fs.StringVar(&cfg.Transport, "transport",
		envOr("SIGNET_MCP_TRANSPORT", TransportStdio),
		"MCP transport: stdio or http (env SIGNET_MCP_TRANSPORT)")
	fs.StringVar(&cfg.Addr, "addr",
		envOr("SIGNET_MCP_ADDR", "localhost:8090"),
		"listen address for the http transport (env SIGNET_MCP_ADDR)")
	fs.StringVar(
		&cfg.PublicURL,
		"public-url",
		envOr("SIGNET_MCP_PUBLIC_URL", ""),
		"externally reachable base URL in http mode; used as the RFC 8707 resource identifier (env SIGNET_MCP_PUBLIC_URL)",
	)
	fs.StringVar(&toolsets, "toolsets",
		envOr("SIGNET_MCP_TOOLSETS", strings.Join(DefaultToolsets, ",")),
		"comma-separated toolsets to enable (env SIGNET_MCP_TOOLSETS)")
	fs.StringVar(&cfg.ClientID, "client-id",
		envOr("SIGNET_MCP_CLIENT_ID", ""),
		"default OAuth client_id for tools that need client credentials (env SIGNET_MCP_CLIENT_ID)")
	fs.StringVar(&cfg.ClientSecret, "client-secret",
		envOr("SIGNET_MCP_CLIENT_SECRET", ""),
		"default OAuth client_secret (env SIGNET_MCP_CLIENT_SECRET)")
	fs.BoolVar(&cfg.CIMDAllowPrivate, "cimd-allow-private-networks",
		envOr("SIGNET_MCP_CIMD_ALLOW_PRIVATE_NETWORKS", "") == "true",
		"allow signet_validate_cimd to fetch documents from private/loopback addresses "+
			"(env SIGNET_MCP_CIMD_ALLOW_PRIVATE_NETWORKS=true)")
	fs.DurationVar(&cfg.HTTPTimeout, "http-timeout", 15*time.Second,
		"timeout for each outbound request to Signet")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", 30*time.Second,
		"graceful shutdown timeout")
	fs.StringVar(&cfg.LogLevel, "log-level",
		envOr("SIGNET_MCP_LOG_LEVEL", "info"),
		"log level: debug, info, warn, error (env SIGNET_MCP_LOG_LEVEL)")
	fs.BoolVar(&cfg.LogJSON, "log-json", false, "emit logs as JSON")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	for t := range strings.SplitSeq(toolsets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			cfg.Toolsets = append(cfg.Toolsets, t)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return errors.New("missing required --issuer (or SIGNET_MCP_ISSUER)")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid issuer URL %q", c.Issuer)
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")

	switch c.Transport {
	case TransportStdio:
	case TransportHTTP:
		if c.PublicURL == "" {
			c.PublicURL = "http://" + c.Addr
		}
		pu, err := url.Parse(c.PublicURL)
		if err != nil || pu.Scheme == "" || pu.Host == "" {
			return fmt.Errorf("invalid public URL %q", c.PublicURL)
		}
		c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	default:
		return fmt.Errorf(
			"invalid transport %q: want %q or %q",
			c.Transport,
			TransportStdio,
			TransportHTTP,
		)
	}

	known := map[string]bool{ToolsetDiagnostics: true, ToolsetFlow: true}
	if len(c.Toolsets) == 0 {
		return errors.New("no toolsets enabled")
	}
	for _, t := range c.Toolsets {
		if !known[t] {
			return fmt.Errorf(
				"unknown toolset %q (available: %s, %s)",
				t,
				ToolsetDiagnostics,
				ToolsetFlow,
			)
		}
	}
	return nil
}
