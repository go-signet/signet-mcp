package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-signet/signet-mcp/internal/signetapi"
)

func TestExplainOAuthErrorInvalidClient(t *testing.T) {
	err := explainOAuthError("token introspection", &signetapi.APIError{
		Code: "invalid_client", Description: "Client authentication failed", StatusCode: 401,
	})
	msg := err.Error()
	for _, want := range []string{"token introspection", "invalid_client", "401", "client authentication failed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "secret-value") {
		t.Error("message must not carry credentials")
	}
}

func TestExplainOAuthErrorPassthrough(t *testing.T) {
	base := errors.New("connection refused")
	err := explainOAuthError("device authorization", base)
	if !errors.Is(err, base) {
		t.Error("non-OAuth errors should be wrapped, not replaced")
	}
}

func TestExplainTokeninfoErrorMentionsAccessType(t *testing.T) {
	err := explainTokeninfoError(&signetapi.APIError{
		Code: "invalid_token", Description: "Token is invalid or expired", StatusCode: 401,
	})
	if !strings.Contains(err.Error(), `type == "access"`) {
		t.Errorf("tokeninfo error should explain the access-type requirement: %v", err)
	}
}
