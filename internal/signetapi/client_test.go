package signetapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeSignet serves a minimal discovery document plus a scripted token and
// device endpoint, capturing the last form it received.
func fakeSignet(t *testing.T, tokenStatus int, tokenBody any) (*httptest.Server, *url.Values) {
	t.Helper()
	lastForm := &url.Values{}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc(
		"/.well-known/openid-configuration",
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{
				"issuer":                        srv.URL,
				"authorization_endpoint":        srv.URL + "/oauth/authorize",
				"token_endpoint":                srv.URL + "/oauth/token",
				"device_authorization_endpoint": srv.URL + "/oauth/device/code",
				"revocation_endpoint":           srv.URL + "/oauth/revoke",
				"jwks_uri":                      srv.URL + "/.well-known/jwks.json",
			})
		},
	)
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		*lastForm = r.PostForm
		writeJSON(t, w, tokenStatus, tokenBody)
	})
	mux.HandleFunc("/oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // RFC 7009: empty body
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, lastForm
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Error(err)
	}
}

func TestTokenRequestSendsResourceAndCredentials(t *testing.T) {
	srv, lastForm := fakeSignet(t, http.StatusOK, map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 60,
	})
	c, err := New(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	tok, err := c.TokenRequest(
		context.Background(),
		form,
		"cid",
		"csecret",
		[]string{"https://mcp.example.com"},
	)
	if err != nil {
		t.Fatalf("TokenRequest: %v", err)
	}
	if tok.AccessToken != "at" {
		t.Errorf("access_token = %q", tok.AccessToken)
	}
	if got := lastForm.Get("resource"); got != "https://mcp.example.com" {
		t.Errorf("resource param = %q", got)
	}
	if lastForm.Get("client_id") != "cid" || lastForm.Get("client_secret") != "csecret" {
		t.Errorf("client credentials not sent in form body: %v", *lastForm)
	}
}

func TestTokenRequestOAuthError(t *testing.T) {
	srv, _ := fakeSignet(t, http.StatusBadRequest, map[string]any{
		"error": "authorization_pending",
	})
	c, err := New(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	_, err = c.TokenRequest(context.Background(), form, "cid", "", nil)
	apiErr := &APIError{}
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "authorization_pending" || apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected error: %+v", apiErr)
	}
}

func TestPostFormAcceptsEmptyBody(t *testing.T) {
	srv, _ := fakeSignet(t, http.StatusOK, nil)
	c, err := New(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("token", "whatever")
	if err := c.PostForm(context.Background(), srv.URL+"/oauth/revoke", form, nil); err != nil {
		t.Errorf("revocation with empty 200 body should succeed: %v", err)
	}
}

func TestHealthUnhealthy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusServiceUnavailable, map[string]any{"status": "unhealthy"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	status, doc, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if status != http.StatusServiceUnavailable || doc["status"] != "unhealthy" {
		t.Errorf("status=%d doc=%v", status, doc)
	}
}

// TestGetJSONRejectsOversizedBody pins the cap behavior: an oversized
// response fails with an explicit size error, never a confusing truncated
// JSON parse error.
func TestGetJSONRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"pad":"`)); err != nil {
			t.Error(err)
		}
		pad := strings.Repeat("x", maxResponseBytes)
		if _, err := w.Write([]byte(pad + `"}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetJSON(context.Background(), srv.URL+"/big.json")
	if err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Errorf("want explicit size-cap error, got %v", err)
	}
}
