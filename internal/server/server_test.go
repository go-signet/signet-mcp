package server

import (
	"context"
	"log/slog"
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
