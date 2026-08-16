package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/go-signet/signet-mcp/internal/config"
)

// TestToolRegistration pins the v1 contract: 15 tools across the two default
// toolsets, with read-only diagnostics correctly annotated.
func TestToolRegistration(t *testing.T) {
	cfg := &config.Config{
		Issuer:      "https://auth.example.com",
		Transport:   config.TransportStdio,
		Toolsets:    config.DefaultToolsets,
		HTTPTimeout: 5 * time.Second,
	}
	srv, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	session, err := srv.mcp.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer session.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}
	want := []string{
		"signet_get_metadata", "signet_get_jwks", "signet_health", "signet_decode_jwt",
		"signet_tokeninfo", "signet_introspect_token", "signet_userinfo",
		"signet_validate_cimd", "signet_revoke_token",
		"signet_device_flow_start", "signet_device_flow_poll", "signet_build_authorize_url",
		"signet_exchange_code", "signet_client_credentials_token", "signet_refresh_token",
	}
	if len(res.Tools) != len(want) {
		t.Errorf("got %d tools, want %d", len(res.Tools), len(want))
	}
	for _, name := range want {
		if byName[name] == nil {
			t.Errorf("missing tool %s", name)
		}
	}
	if a := byName["signet_get_metadata"].Annotations; a == nil || !a.ReadOnlyHint {
		t.Error("signet_get_metadata should be annotated read-only")
	}
	if a := byName["signet_revoke_token"].Annotations; a == nil || a.ReadOnlyHint ||
		a.DestructiveHint == nil || *a.DestructiveHint || !a.IdempotentHint {
		t.Error("signet_revoke_token should be a non-destructive idempotent write")
	}
}

// TestHTTPServerHealthz pins the container liveness contract: /healthz
// answers 200 without a token while the MCP endpoint stays behind auth.
func TestHTTPServerHealthz(t *testing.T) {
	var issuer string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuer,
				"jwks_uri":               issuer + "/jwks",
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
			})
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()
	issuer = fake.URL

	cfg := &config.Config{
		Issuer:      fake.URL,
		Transport:   config.TransportHTTP,
		Addr:        "localhost:0",
		PublicURL:   "http://localhost:8090",
		Toolsets:    config.DefaultToolsets,
		HTTPTimeout: 5 * time.Second,
	}
	srv, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv, err := srv.HTTPServer(context.Background())
	if err != nil {
		t.Fatalf("HTTPServer: %v", err)
	}

	rr := httptest.NewRecorder()
	httpSrv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "ok" {
		t.Errorf("GET /healthz body = %q, want %q", got, "ok")
	}

	rr = httptest.NewRecorder()
	httpSrv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated POST / = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestDiagnosticsOnlyToolset checks the toolset switch actually gates
// registration.
func TestDiagnosticsOnlyToolset(t *testing.T) {
	cfg := &config.Config{
		Issuer:      "https://auth.example.com",
		Transport:   config.TransportStdio,
		Toolsets:    []string{config.ToolsetDiagnostics},
		HTTPTimeout: 5 * time.Second,
	}
	srv, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.mcp.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).
		Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 9 {
		t.Errorf("diagnostics-only session should expose 9 tools, got %d", len(res.Tools))
	}
	for _, tool := range res.Tools {
		if tool.Name == "signet_device_flow_start" {
			t.Error("flow toolset leaked into a diagnostics-only session")
		}
	}
}
