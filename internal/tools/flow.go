package tools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/go-signet/signet-mcp/internal/signetapi"
)

// registerFlow adds the `flow` toolset (tools 10–15).
func registerFlow(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_device_flow_start",
		Description: "Start an RFC 8628 Device Code flow: returns user_code, verification_uri and device_code. " +
			"Supports the RFC 8707 resource parameter for audience binding. " +
			"Have the user visit the verification URI, then call signet_device_flow_poll.",
		Annotations: write("Start device flow (RFC 8628)", false),
	}, d.deviceFlowStart)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_device_flow_poll",
		Description: "Poll the token endpoint for a device flow result — a single poll by default, or keep " +
			"polling for wait_seconds. Interprets authorization_pending, expired_token and access_denied.",
		Annotations: write("Poll device flow token", false),
	}, d.deviceFlowPoll)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_build_authorize_url",
		Description: "Generate a PKCE verifier/challenge (S256) locally and build the /oauth/authorize URL, " +
			"including state and the optional RFC 8707 resource parameter. Nothing is sent to the server. " +
			"Keep the returned code_verifier for signet_exchange_code.",
		Annotations: readOnly("Build authorize URL with PKCE"),
	}, d.buildAuthorizeURL)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_exchange_code",
		Description: "Exchange an authorization code (plus PKCE code_verifier) for tokens. If the callback's " +
			"RFC 9207 iss parameter is supplied it is checked against the configured issuer to detect mix-up attacks.",
		Annotations: write("Exchange authorization code", false),
	}, d.exchangeCode)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_client_credentials_token",
		Description: "Obtain a machine-to-machine token via the client_credentials grant and decode its audience " +
			"and scopes, verifying the client configuration. Supports the RFC 8707 resource parameter.",
		Annotations: write("Get client-credentials token", false),
	}, d.clientCredentialsToken)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_refresh_token",
		Description: "Redeem a refresh token and report whether rotation is on (a new refresh token was issued) " +
			"and how the access-token audience was narrowed per RFC 8707 §2.2 when a resource is requested.",
		Annotations: write("Refresh a token", false),
	}, d.refreshToken)
}

// tokenOut is the common rendering of an RFC 6749 token response. The
// unverified claims of the access token are included so callers can inspect
// audience binding without another tool call.
type tokenOut struct {
	AccessToken       string         `json:"access_token"`
	RefreshToken      string         `json:"refresh_token,omitempty"`
	TokenType         string         `json:"token_type,omitempty"`
	ExpiresIn         int            `json:"expires_in,omitempty"`
	ExpiresAt         string         `json:"expires_at,omitempty"`
	Scope             string         `json:"scope,omitempty"`
	IDTokenIssued     bool           `json:"id_token_issued,omitempty"`
	AccessTokenClaims map[string]any `json:"access_token_claims,omitempty" jsonschema:"unverified decoded JWT claims of the access token"`
}

func renderToken(t *signetapi.TokenResponse) tokenOut {
	out := tokenOut{
		AccessToken: t.AccessToken, RefreshToken: t.RefreshToken,
		TokenType: t.TokenType, ExpiresIn: t.ExpiresIn, Scope: t.Scope,
		IDTokenIssued: t.IDToken != "",
	}
	if t.ExpiresIn > 0 {
		out.ExpiresAt = time.Now().
			Add(time.Duration(t.ExpiresIn) * time.Second).
			UTC().
			Format(time.RFC3339)
	}
	if _, claims, err := decodeJWTParts(t.AccessToken); err == nil {
		out.AccessTokenClaims = claims
	}
	return out
}

func resourceList(resource string) []string {
	if resource == "" {
		return nil
	}
	return []string{resource}
}

// --- 10. signet_device_flow_start ---------------------------------------

type deviceStartIn struct {
	ClientID     string   `json:"client_id,omitempty"     jsonschema:"OAuth client_id; defaults to the configured client"`
	ClientSecret string   `json:"client_secret,omitempty" jsonschema:"client_secret, only for confidential clients"`
	Scopes       []string `json:"scopes,omitempty"        jsonschema:"scopes to request; empty means the client's full scope set"`
	Resource     string   `json:"resource,omitempty"      jsonschema:"RFC 8707 resource identifier to bind the token audience to"`
}

type deviceStartOut struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	ExpiresAt               string `json:"expires_at"`
	Interval                int    `json:"interval"`
	NextStep                string `json:"next_step"`
}

func (d *Deps) deviceFlowStart(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in deviceStartIn,
) (*mcp.CallToolResult, deviceStartOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" {
		return nil, deviceStartOut{}, errors.New(
			"device flow requires a client_id: pass one or start signet-mcp with --client-id",
		)
	}
	da, err := d.API.DeviceCodeRequest(
		ctx, clientID, clientSecret, in.Scopes, resourceList(in.Resource),
	)
	if err != nil {
		return nil, deviceStartOut{}, explainOAuthError("device authorization", err)
	}
	interval := da.Interval
	if interval == 0 {
		interval = 5
	}
	return nil, deviceStartOut{
		DeviceCode:              da.DeviceCode,
		UserCode:                da.UserCode,
		VerificationURI:         da.VerificationURI,
		VerificationURIComplete: da.VerificationURIComplete,
		ExpiresIn:               da.ExpiresIn,
		ExpiresAt: time.Now().
			Add(time.Duration(da.ExpiresIn) * time.Second).
			UTC().
			Format(time.RFC3339),
		Interval: interval,
		NextStep: fmt.Sprintf(
			"Have the user open %s and enter code %s (or open %s directly), then call "+
				"signet_device_flow_poll with the device_code every %d seconds.",
			da.VerificationURI,
			da.UserCode,
			da.VerificationURIComplete,
			interval,
		),
	}, nil
}

// --- 11. signet_device_flow_poll ----------------------------------------

type devicePollIn struct {
	DeviceCode      string `json:"device_code"                jsonschema:"the device_code returned by signet_device_flow_start"`
	ClientID        string `json:"client_id,omitempty"        jsonschema:"OAuth client_id; defaults to the configured client"`
	ClientSecret    string `json:"client_secret,omitempty"    jsonschema:"client_secret, only for confidential clients"`
	WaitSeconds     int    `json:"wait_seconds,omitempty"     jsonschema:"0 (default) polls once; otherwise keep polling up to this many seconds (max 300)"`
	IntervalSeconds int    `json:"interval_seconds,omitempty" jsonschema:"seconds between polls, default 5; raised automatically on slow_down"`
}

type devicePollOut struct {
	Status      string    `json:"status"          jsonschema:"authorized | pending | denied | expired"`
	Explanation string    `json:"explanation"`
	Token       *tokenOut `json:"token,omitempty"`
}

func (d *Deps) deviceFlowPoll(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in devicePollIn,
) (*mcp.CallToolResult, devicePollOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" {
		return nil, devicePollOut{}, errors.New(
			"device flow requires a client_id: pass one or start signet-mcp with --client-id",
		)
	}
	interval := time.Duration(max(in.IntervalSeconds, 1)) * time.Second
	if in.IntervalSeconds == 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(min(in.WaitSeconds, 300)) * time.Second)

	for {
		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", in.DeviceCode)
		tok, err := d.API.TokenRequest(ctx, form, clientID, clientSecret, nil)
		if err == nil {
			t := renderToken(tok)
			return nil, devicePollOut{
				Status:      "authorized",
				Explanation: "the user approved the request",
				Token:       &t,
			}, nil
		}
		apiErr := &signetapi.APIError{}
		if !errors.As(err, &apiErr) {
			return nil, devicePollOut{}, explainOAuthError("device flow polling", err)
		}
		switch apiErr.Code {
		case "authorization_pending", "slow_down":
			reason := "the user has not finished authorizing yet (RFC 8628 authorization_pending)"
			if apiErr.Code == "slow_down" {
				// RFC 8628 §3.5: back off by 5 seconds and never poll
				// again without waiting the new interval first.
				interval += 5 * time.Second
				reason = "the server asked to poll less often (RFC 8628 slow_down) — interval raised by 5 seconds"
			}
			if time.Now().Add(interval).Before(deadline) {
				select {
				case <-ctx.Done():
					return nil, devicePollOut{}, ctx.Err()
				case <-time.After(interval):
				}
				continue
			}
			return nil, devicePollOut{
				Status: "pending",
				Explanation: fmt.Sprintf(
					"%s — poll again in %d seconds", reason, int(interval.Seconds()),
				),
			}, nil
		case "access_denied":
			return nil, devicePollOut{
				Status:      "denied",
				Explanation: "the user (or server policy) denied the request",
			}, nil
		case "expired_token":
			return nil, devicePollOut{
				Status:      "expired",
				Explanation: "the device code expired before the user authorized — start over with signet_device_flow_start",
			}, nil
		default:
			return nil, devicePollOut{}, explainOAuthError("device flow polling", err)
		}
	}
}

// --- 12. signet_build_authorize_url -------------------------------------

type buildAuthorizeIn struct {
	ClientID    string   `json:"client_id,omitempty" jsonschema:"OAuth client_id; defaults to the configured client"`
	RedirectURI string   `json:"redirect_uri"        jsonschema:"registered redirect URI the code will be delivered to"`
	Scopes      []string `json:"scopes,omitempty"`
	State       string   `json:"state,omitempty"     jsonschema:"CSRF state; generated when omitted"`
	Nonce       string   `json:"nonce,omitempty"     jsonschema:"OIDC nonce for the id_token"`
	Resource    string   `json:"resource,omitempty"  jsonschema:"RFC 8707 resource identifier to bind the token audience to"`
}

type buildAuthorizeOut struct {
	AuthorizeURL  string `json:"authorize_url"`
	CodeVerifier  string `json:"code_verifier"  jsonschema:"keep this secret; pass it to signet_exchange_code"`
	CodeChallenge string `json:"code_challenge"`
	State         string `json:"state"`
	Note          string `json:"note"`
}

func (d *Deps) buildAuthorizeURL(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in buildAuthorizeIn,
) (*mcp.CallToolResult, buildAuthorizeOut, error) {
	clientID, _ := d.clientCreds(in.ClientID, "")
	if clientID == "" {
		return nil, buildAuthorizeOut{}, errors.New(
			"pass a client_id or start signet-mcp with --client-id",
		)
	}
	eps, err := d.API.Endpoints(ctx)
	if err != nil {
		return nil, buildAuthorizeOut{}, err
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		return nil, buildAuthorizeOut{}, err
	}
	state := in.State
	if state == "" {
		if state, err = randomToken(16); err != nil {
			return nil, buildAuthorizeOut{}, err
		}
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", in.RedirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(in.Scopes) > 0 {
		q.Set("scope", strings.Join(in.Scopes, " "))
	}
	if in.Nonce != "" {
		q.Set("nonce", in.Nonce)
	}
	if in.Resource != "" {
		q.Add("resource", in.Resource)
	}
	return nil, buildAuthorizeOut{
		AuthorizeURL:  eps.AuthorizeURL + "?" + q.Encode(),
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		State:         state,
		Note: "Open the URL in a browser (a Signet login session is required). After consent, the callback carries " +
			"code, state and the RFC 9207 iss parameter — verify state matches, then call signet_exchange_code " +
			"with the code, this code_verifier, the same redirect_uri and the callback's iss.",
	}, nil
}

// newPKCE generates an RFC 7636 S256 verifier/challenge pair.
func newPKCE() (verifier, challenge string, err error) {
	verifier, err = randomToken(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// randomToken returns n random bytes as unpadded base64url.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- 13. signet_exchange_code -------------------------------------------

type exchangeCodeIn struct {
	Code         string `json:"code"                    jsonschema:"the authorization code from the callback"`
	RedirectURI  string `json:"redirect_uri"            jsonschema:"must equal the redirect_uri used at /oauth/authorize"`
	CodeVerifier string `json:"code_verifier"           jsonschema:"the PKCE verifier from signet_build_authorize_url"`
	ClientID     string `json:"client_id,omitempty"     jsonschema:"OAuth client_id; defaults to the configured client"`
	ClientSecret string `json:"client_secret,omitempty" jsonschema:"client_secret, only for confidential clients"`
	Resource     string `json:"resource,omitempty"      jsonschema:"RFC 8707 resource; must not exceed what was granted at /oauth/authorize"`
	Iss          string `json:"iss,omitempty"           jsonschema:"the iss parameter from the callback, for RFC 9207 mix-up detection"`
}

type exchangeCodeOut struct {
	Token       tokenOut `json:"token"`
	IssuerCheck string   `json:"issuer_check"`
}

func (d *Deps) exchangeCode(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in exchangeCodeIn,
) (*mcp.CallToolResult, exchangeCodeOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" {
		return nil, exchangeCodeOut{}, errors.New(
			"pass a client_id or start signet-mcp with --client-id",
		)
	}
	issuerCheck := "not performed — the callback's iss parameter was not supplied (RFC 9207)"
	if in.Iss != "" {
		if in.Iss != d.API.Issuer() {
			return nil, exchangeCodeOut{}, fmt.Errorf(
				"RFC 9207 issuer mismatch: the callback claims iss=%q but this "+
					"server is configured for %q — possible authorization-server mix-up attack; do not use the code",
				in.Iss,
				d.API.Issuer(),
			)
		}
		issuerCheck = "passed — callback iss matches the configured issuer (RFC 9207)"
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", in.Code)
	form.Set("redirect_uri", in.RedirectURI)
	form.Set("code_verifier", in.CodeVerifier)
	tok, err := d.API.TokenRequest(ctx, form, clientID, clientSecret, resourceList(in.Resource))
	if err != nil {
		return nil, exchangeCodeOut{}, explainOAuthError("authorization code exchange", err)
	}
	return nil, exchangeCodeOut{Token: renderToken(tok), IssuerCheck: issuerCheck}, nil
}

// --- 14. signet_client_credentials_token --------------------------------

type clientCredsIn struct {
	ClientID     string   `json:"client_id,omitempty"     jsonschema:"confidential OAuth client_id; defaults to the configured client"`
	ClientSecret string   `json:"client_secret,omitempty" jsonschema:"client_secret for the given client_id"`
	Scopes       []string `json:"scopes,omitempty"`
	Resource     string   `json:"resource,omitempty"      jsonschema:"RFC 8707 resource; must be in the client's allowed resource list"`
}

type clientCredsOut struct {
	Token tokenOut `json:"token"`
	Note  string   `json:"note"`
}

func (d *Deps) clientCredentialsToken(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in clientCredsIn,
) (*mcp.CallToolResult, clientCredsOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" || clientSecret == "" {
		return nil, clientCredsOut{}, errors.New(
			"client_credentials requires a confidential client: pass " +
				"client_id and client_secret or configure them at startup",
		)
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if len(in.Scopes) > 0 {
		form.Set("scope", strings.Join(in.Scopes, " "))
	}
	tok, err := d.API.TokenRequest(ctx, form, clientID, clientSecret, resourceList(in.Resource))
	if err != nil {
		return nil, clientCredsOut{}, explainOAuthError("client_credentials grant", err)
	}
	return nil, clientCredsOut{
		Token: renderToken(tok),
		Note: "the client configuration works for machine-to-machine tokens; check access_token_claims.aud to " +
			"confirm the audience matches the requested resource",
	}, nil
}

// --- 15. signet_refresh_token -------------------------------------------

type refreshIn struct {
	RefreshToken string   `json:"refresh_token"`
	ClientID     string   `json:"client_id,omitempty"     jsonschema:"OAuth client_id; defaults to the configured client"`
	ClientSecret string   `json:"client_secret,omitempty" jsonschema:"client_secret, required for confidential clients"`
	Scopes       []string `json:"scopes,omitempty"        jsonschema:"optional scope narrowing"`
	Resource     string   `json:"resource,omitempty"      jsonschema:"RFC 8707 resource; per §2.2 refresh may only narrow the original audience, never widen it"`
}

type refreshOut struct {
	Token           tokenOut `json:"token"`
	RotationEnabled bool     `json:"rotation_enabled" jsonschema:"true when the server issued a new refresh token (rotation mode)"`
	Notes           []string `json:"notes"`
}

func (d *Deps) refreshToken(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in refreshIn,
) (*mcp.CallToolResult, refreshOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" {
		return nil, refreshOut{}, errors.New(
			"pass a client_id or start signet-mcp with --client-id",
		)
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", in.RefreshToken)
	if len(in.Scopes) > 0 {
		form.Set("scope", strings.Join(in.Scopes, " "))
	}
	tok, err := d.API.TokenRequest(ctx, form, clientID, clientSecret, resourceList(in.Resource))
	if err != nil {
		return nil, refreshOut{}, explainOAuthError("refresh_token grant", err)
	}
	out := refreshOut{Token: renderToken(tok)}
	switch tok.RefreshToken {
	case "":
		out.Notes = append(
			out.Notes,
			"no refresh token in the response — the server kept the existing one valid (fixed mode)",
		)
	case in.RefreshToken:
		out.Notes = append(
			out.Notes,
			"the same refresh token was returned — rotation is off (fixed mode)",
		)
	default:
		out.RotationEnabled = true
		out.Notes = append(
			out.Notes,
			"a NEW refresh token was issued (rotation mode) — the old one is revoked; "+
				"replaying it would revoke the whole token family (RFC 6819 §4.14.2)",
		)
	}
	if in.Resource != "" {
		out.Notes = append(
			out.Notes,
			"resource requested: per RFC 8707 §2.2 the access-token audience can only be "+
				"narrowed relative to the original grant — check access_token_claims.aud",
		)
	}
	return nil, out, nil
}
