package tools

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// signHS256 builds a compact JWT for tests.
func signHS256(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestDecodeJWTParts(t *testing.T) {
	tok := signHS256(t, map[string]any{"iss": "https://a", "type": "access"}, "k")
	header, claims, err := decodeJWTParts(tok)
	if err != nil {
		t.Fatalf("decodeJWTParts: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Errorf("alg = %v", header["alg"])
	}
	if claims["type"] != "access" {
		t.Errorf("type = %v", claims["type"])
	}
}

func TestDecodeJWTPartsRejectsOpaque(t *testing.T) {
	_, _, err := decodeJWTParts("sgk_abc123")
	if err == nil || !strings.Contains(err.Error(), "3 dot-separated segments") {
		t.Errorf("want segment error, got %v", err)
	}
}

func TestCheckClaimsRefreshToken(t *testing.T) {
	claims := map[string]any{
		"iss":  "https://auth.example.com",
		"exp":  float64(time.Now().Add(time.Hour).Unix()),
		"type": "refresh",
	}
	checks := checkClaims(claims, "https://auth.example.com", "")
	byName := map[string]claimCheck{}
	for _, c := range checks {
		byName[c.Name] = c
	}
	if !byName["iss"].OK || !byName["exp"].OK {
		t.Errorf("iss/exp should pass: %+v", checks)
	}
	tc := byName["type"]
	if tc.OK || !strings.Contains(tc.Detail, "refresh token") {
		t.Errorf("type check should fail with a refresh-token explanation, got %+v", tc)
	}
}

func TestCheckClaimsExpiredAndWrongAudience(t *testing.T) {
	claims := map[string]any{
		"iss":  "https://other.example.com",
		"exp":  float64(time.Now().Add(-time.Minute).Unix()),
		"aud":  []any{"https://api.example.com"},
		"type": "access",
	}
	checks := checkClaims(claims, "https://auth.example.com", "https://mcp.example.com")
	for _, c := range checks {
		switch c.Name {
		case "iss", "exp", "aud":
			if c.OK {
				t.Errorf("%s should fail: %+v", c.Name, c)
			}
		case "type":
			if !c.OK {
				t.Errorf("type should pass: %+v", c)
			}
		}
	}
}

func TestDiffMetadata(t *testing.T) {
	as := map[string]any{
		"issuer":                 "https://a",
		"introspection_endpoint": "https://a/oauth/introspect",
	}
	oidc := map[string]any{"issuer": "https://a", "userinfo_endpoint": "https://a/oauth/userinfo"}
	diffs := diffMetadata(as, oidc)
	joined := strings.Join(diffs, "\n")
	if !strings.Contains(joined, `"introspection_endpoint" only in oauth-authorization-server`) {
		t.Errorf("missing introspection diff: %v", diffs)
	}
	if !strings.Contains(joined, `"userinfo_endpoint" only in openid-configuration`) {
		t.Errorf("missing userinfo diff: %v", diffs)
	}
	if strings.Contains(joined, `"issuer"`) {
		t.Errorf("issuer should not differ: %v", diffs)
	}
}

func TestNewPKCE(t *testing.T) {
	verifier, challenge, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Errorf("challenge = %q, want S256 of verifier %q", challenge, want)
	}
	if len(verifier) < 43 {
		t.Errorf("verifier too short for RFC 7636: %d chars", len(verifier))
	}
}
