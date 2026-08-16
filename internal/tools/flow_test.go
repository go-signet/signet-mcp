package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeFlowServer serves a minimal discovery document plus scripted device
// and token endpoints, capturing the last form each received.
func fakeFlowServer(t *testing.T, tokenHandler http.HandlerFunc) (*httptest.Server, *url.Values) {
	t.Helper()
	lastDeviceForm := &url.Values{}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc(
		"/.well-known/openid-configuration",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]any{
				"issuer":                        srv.URL,
				"authorization_endpoint":        srv.URL + "/oauth/authorize",
				"token_endpoint":                srv.URL + "/oauth/token",
				"device_authorization_endpoint": srv.URL + "/oauth/device/code",
			})
			if err != nil {
				t.Error(err)
			}
		},
	)
	mux.HandleFunc("/oauth/device/code", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		*lastDeviceForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc", "user_code": "UC-1",
			"verification_uri": srv.URL + "/device", "expires_in": 600, "interval": 5,
		})
		if err != nil {
			t.Error(err)
		}
	})
	if tokenHandler != nil {
		mux.HandleFunc("/oauth/token", tokenHandler)
	}
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, lastDeviceForm
}

// TestDeviceFlowStartForwardsClientSecret pins the regression where the
// device authorization request dropped the caller's client_secret, locking
// confidential clients out of the device flow.
func TestDeviceFlowStartForwardsClientSecret(t *testing.T) {
	srv, lastForm := fakeFlowServer(t, nil)
	d := testDeps(t, srv.URL)
	_, out, err := d.deviceFlowStart(context.Background(), nil, deviceStartIn{
		ClientID: "conf-client", ClientSecret: "conf-secret",
	})
	if err != nil {
		t.Fatalf("deviceFlowStart: %v", err)
	}
	if out.UserCode != "UC-1" {
		t.Errorf("user_code = %q", out.UserCode)
	}
	if got := lastForm.Get("client_secret"); got != "conf-secret" {
		t.Errorf("client_secret not forwarded to the device endpoint, form = %v", *lastForm)
	}
}

// TestDeviceFlowPollSlowDownDoesNotHotLoop pins the RFC 8628 §3.5
// regression: on slow_down with wait_seconds=0 the old code re-polled in a
// tight loop forever; the fixed code raises the interval and returns a
// pending result after a single request.
func TestDeviceFlowPollSlowDownDoesNotHotLoop(t *testing.T) {
	var polls atomic.Int32
	srv, _ := fakeFlowServer(t, func(w http.ResponseWriter, _ *http.Request) {
		polls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]any{"error": "slow_down"}); err != nil {
			t.Error(err)
		}
	})
	d := testDeps(t, srv.URL)
	_, out, err := d.deviceFlowPoll(context.Background(), nil, devicePollIn{
		DeviceCode: "dc", ClientID: "c", WaitSeconds: 0,
	})
	if err != nil {
		t.Fatalf("deviceFlowPoll: %v", err)
	}
	if out.Status != "pending" {
		t.Errorf("status = %q, want pending", out.Status)
	}
	if !strings.Contains(out.Explanation, "slow_down") {
		t.Errorf("explanation should mention slow_down: %q", out.Explanation)
	}
	if got := polls.Load(); got != 1 {
		t.Errorf("token endpoint polled %d times in a single-poll call, want 1", got)
	}
}

// TestVerifierRetriesAfterTransientFailure pins the lazy-init behavior: a
// failed discovery must not be cached, so a later call succeeds once the
// issuer recovers.
func TestVerifierRetriesAfterTransientFailure(t *testing.T) {
	var calls atomic.Int32
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc(
		"/.well-known/openid-configuration",
		func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/oauth/authorize",
				"token_endpoint":         srv.URL + "/oauth/token",
				"jwks_uri":               srv.URL + "/.well-known/jwks.json",
			})
			if err != nil {
				t.Error(err)
			}
		},
	)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	d := testDeps(t, srv.URL)
	if _, err := d.verifier(); err == nil {
		t.Fatal("first verifier() should fail while discovery returns 500")
	}
	v, err := d.verifier()
	if err != nil {
		t.Fatalf("second verifier() should succeed after the issuer recovers, got %v", err)
	}
	if v == nil {
		t.Fatal("verifier is nil")
	}
}
