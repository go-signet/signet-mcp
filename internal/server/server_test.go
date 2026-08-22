package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// fakeIssuer is an OIDC issuer stub with a real RSA JWKS so the offline
// verifier can validate tokens minted by sign.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	fi := &fakeIssuer{key: key}
	fi.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 fi.srv.URL,
				"jwks_uri":               fi.srv.URL + "/jwks",
				"authorization_endpoint": fi.srv.URL + "/authorize",
				"token_endpoint":         fi.srv.URL + "/token",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fi.srv.Close)
	return fi
}

// sign mints an RS256 JWT from this issuer with the given aud and Signet
// token type. aud == nil omits the claim entirely.
func (fi *fakeIssuer) sign(t *testing.T, aud []string, typ string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: fi.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	now := time.Now()
	claims := map[string]any{
		"iss":   fi.srv.URL,
		"sub":   "user-1",
		"uid":   "user-1",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"type":  typ,
		"scope": "openid",
	}
	if aud != nil {
		claims["aud"] = aud
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

// TestHTTPServerAudience pins the RFC 8707 audience contract, including the
// trailing-slash tolerance: MCP clients request resource=new URL(serverUrl).href,
// which turns a bare-origin public URL into one ending in "/", and the token
// they come back with must still be accepted.
func TestHTTPServerAudience(t *testing.T) {
	fi := newFakeIssuer(t)
	const publicURL = "http://localhost:8090"

	cfg := &config.Config{
		Issuer:      fi.srv.URL,
		Transport:   config.TransportHTTP,
		Addr:        "localhost:0",
		PublicURL:   publicURL,
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

	const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` +
		`"protocolVersion":"2025-06-18","capabilities":{},` +
		`"clientInfo":{"name":"test","version":"0"}}}`

	tests := []struct {
		name     string
		aud      []string
		typ      string
		wantAuth bool
	}{
		{"exact", []string{publicURL}, "access", true},
		{"trailing slash", []string{publicURL + "/"}, "access", true},
		{"multi-valued", []string{"https://other.example", publicURL + "/"}, "access", true},
		{"other resource", []string{"http://localhost:8091"}, "access", false},
		{"prefix only", []string{publicURL + "/mcp"}, "access", false},
		{"missing aud", nil, "access", false},
		{"refresh token", []string{publicURL}, "refresh", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(initBody))
			req.Header.Set("Authorization", "Bearer "+fi.sign(t, tt.aud, tt.typ))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			rr := httptest.NewRecorder()
			httpSrv.Handler.ServeHTTP(rr, req)

			if tt.wantAuth && rr.Code == http.StatusUnauthorized {
				t.Fatalf("aud %v rejected: %d %s", tt.aud, rr.Code, rr.Body.String())
			}
			if !tt.wantAuth && rr.Code != http.StatusUnauthorized {
				t.Fatalf("aud %v type %q accepted: %d %s",
					tt.aud, tt.typ, rr.Code, rr.Body.String())
			}
			if tt.wantAuth && rr.Code != http.StatusOK {
				t.Fatalf("initialize = %d, want 200: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestAudienceAllowed(t *testing.T) {
	tests := []struct {
		aud      []string
		resource string
		want     bool
	}{
		{[]string{"http://h:1"}, "http://h:1", true},
		{[]string{"http://h:1/"}, "http://h:1", true},
		{[]string{"http://h:1"}, "http://h:1/", true},
		{[]string{"http://h:1/mcp"}, "http://h:1/mcp/", true},
		{[]string{"x", "http://h:1"}, "http://h:1", true},
		{[]string{"http://h:1//"}, "http://h:1", false},
		{[]string{"http://h:1/mcp"}, "http://h:1", false},
		{[]string{"http://h:10"}, "http://h:1", false},
		{nil, "http://h:1", false},
		{[]string{""}, "", true},
	}
	for _, tt := range tests {
		if got := audienceAllowed(tt.aud, tt.resource); got != tt.want {
			t.Errorf("audienceAllowed(%v, %q) = %v, want %v", tt.aud, tt.resource, got, tt.want)
		}
	}
}
