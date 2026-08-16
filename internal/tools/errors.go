package tools

import (
	"errors"
	"fmt"

	"github.com/go-signet/sdk-go/oauth"

	"github.com/go-signet/signet-mcp/internal/signetapi"
)

// oauthErrorHints maps RFC 6749/8628 error codes to actionable explanations.
// Hints must never echo credentials or tokens back to the model.
var oauthErrorHints = map[string]string{
	"invalid_client": "client authentication failed — the client_id is unknown or the client_secret is wrong " +
		"(credentials are not echoed back; re-check them at the source)",
	"invalid_grant": "the grant (code, refresh token, or device code) is invalid, expired, revoked, " +
		"already used, or was issued to a different client",
	"invalid_request":        "the request is missing a required parameter or a parameter is malformed",
	"invalid_scope":          "a requested scope is unknown or not allowed for this client",
	"invalid_target":         "the requested RFC 8707 resource is not in this client's allowed resource list",
	"unauthorized_client":    "this client is not allowed to use the requested grant type",
	"unsupported_grant_type": "the server does not support the requested grant type",
	"access_denied":          "the user (or the server policy) denied the authorization request",
	"authorization_pending":  "the user has not finished authorizing yet — keep polling at the advertised interval",
	"slow_down":              "polling too fast — increase the polling interval by 5 seconds (RFC 8628 §3.5)",
	"expired_token":          "the device code expired before the user authorized — restart the device flow",
	"invalid_token": "the token is invalid for this endpoint — it may be expired, revoked, malformed, " +
		"or of the wrong type (e.g. a refresh token where an access token is required)",
}

// explainOAuthError rewrites an error from Signet into a readable, safe tool
// error. what names the operation, e.g. "token introspection".
func explainOAuthError(what string, err error) error {
	var code, desc string
	var status int
	apiErr := &signetapi.APIError{}
	sdkErr := &oauth.Error{}
	switch {
	case errors.As(err, &apiErr):
		code, desc, status = apiErr.Code, apiErr.Description, apiErr.StatusCode
	case errors.As(err, &sdkErr):
		code, desc, status = sdkErr.Code, sdkErr.Description, sdkErr.StatusCode
	default:
		return fmt.Errorf("%s failed: %w", what, err)
	}
	msg := fmt.Sprintf("%s failed: Signet returned %q (HTTP %d)", what, code, status)
	if desc != "" {
		msg += ": " + desc
	}
	if hint, ok := oauthErrorHints[code]; ok {
		msg += ". Hint: " + hint
	}
	return errors.New(msg)
}
