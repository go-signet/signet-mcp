package tools

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-signet/signet-mcp/internal/config"
	"github.com/go-signet/signet-mcp/internal/signetapi"
)

func testDeps(t *testing.T, issuer string) *Deps {
	t.Helper()
	cfg := &config.Config{Issuer: issuer, HTTPTimeout: 5_000_000_000}
	api, err := signetapi.New(issuer, cfg.HTTPTimeout)
	if err != nil {
		t.Fatal(err)
	}
	return NewDeps(api, cfg, slog.New(slog.DiscardHandler))
}

// cimdServer serves a CIMD document whose client_id is patched to the test
// server's own URL when the placeholder is used.
func cimdServer(t *testing.T, doc map[string]any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if doc["client_id"] == "SELF" {
			doc["client_id"] = srv.URL + r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestValidateCIMDHappyPath(t *testing.T) {
	srv := cimdServer(t, map[string]any{
		"client_id":     "SELF",
		"client_name":   "Test MCP client",
		"redirect_uris": []string{"https://client.example.com/callback"},
		"grant_types":   []string{"authorization_code"},
	})
	d := testDeps(t, "https://unused.example.com")
	_, out, err := d.validateCIMD(
		context.Background(),
		nil,
		validateCIMDIn{URL: srv.URL + "/client.json"},
	)
	if err != nil {
		t.Fatalf("validateCIMD: %v", err)
	}
	// The httptest server is plain http, so the scheme check must fail but
	// everything else should pass.
	for _, c := range out.Checks {
		if c.Name == "url_scheme" {
			if c.OK {
				t.Error("url_scheme should fail for http://")
			}
			continue
		}
		if !c.OK {
			t.Errorf("check %s failed: %s", c.Name, c.Detail)
		}
	}
	if out.Valid {
		t.Error("Valid should be false because the URL is not https")
	}
}

func TestValidateCIMDRejectsSecretAndMismatch(t *testing.T) {
	srv := cimdServer(t, map[string]any{
		"client_id":                  "https://elsewhere.example.com/other.json",
		"client_secret":              "oops",
		"token_endpoint_auth_method": "client_secret_post",
		"redirect_uris":              []string{"https://client.example.com/callback"},
	})
	d := testDeps(t, "https://unused.example.com")
	_, out, err := d.validateCIMD(
		context.Background(),
		nil,
		validateCIMDIn{URL: srv.URL + "/client.json"},
	)
	if err != nil {
		t.Fatalf("validateCIMD: %v", err)
	}
	failed := map[string]bool{}
	for _, c := range out.Checks {
		if !c.OK {
			failed[c.Name] = true
		}
	}
	for _, want := range []string{"client_id_matches_url", "no_client_secret", "token_endpoint_auth_method"} {
		if !failed[want] {
			t.Errorf("check %s should have failed; failed set: %v", want, failed)
		}
	}
}

func TestValidateCIMDFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	d := testDeps(t, "https://unused.example.com")
	_, out, err := d.validateCIMD(
		context.Background(),
		nil,
		validateCIMDIn{URL: srv.URL + "/missing.json"},
	)
	if err != nil {
		t.Fatalf("fetch failures should be reported via checks, got hard error: %v", err)
	}
	if out.Valid {
		t.Error("Valid should be false on a 404")
	}
}

// TestValidateCIMDNonJSONContentType asserts a non-JSON Content-Type is a
// failing check that invalidates the result, while the rest of the document
// is still validated for a complete diagnostic report.
func TestValidateCIMDNonJSONContentType(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		doc := map[string]any{
			"client_id":     srv.URL + r.URL.Path,
			"redirect_uris": []string{"https://client.example.com/callback"},
		}
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	d := testDeps(t, "https://unused.example.com")
	_, out, err := d.validateCIMD(
		context.Background(),
		nil,
		validateCIMDIn{URL: srv.URL + "/client.json"},
	)
	if err != nil {
		t.Fatalf("validateCIMD: %v", err)
	}
	if out.Valid {
		t.Error("Valid must be false when Content-Type is not application/json")
	}
	sawContentType, sawClientID := false, false
	for _, c := range out.Checks {
		if c.Name == "content_type" && !c.OK {
			sawContentType = true
		}
		if c.Name == "client_id_matches_url" && c.OK {
			sawClientID = true
		}
	}
	if !sawContentType {
		t.Error("content_type check should be present and failing")
	}
	if !sawClientID {
		t.Error("later checks should still run after a content-type failure")
	}
}
