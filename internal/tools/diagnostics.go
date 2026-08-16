package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/go-signet/signet-mcp/internal/signetapi"
)

// registerDiagnostics adds the `diagnostics` toolset (tools 1–9).
func registerDiagnostics(s *mcp.Server, d *Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_get_metadata",
		Description: "Fetch the Signet authorization-server metadata (RFC 8414) and the OIDC discovery " +
			"document, and report any differences between the two.",
		Annotations: readOnly("Get Signet server metadata"),
	}, d.getMetadata)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "signet_get_jwks",
		Description: "Fetch the Signet JWKS document and list each public key's kid, kty, alg, use and crv.",
		Annotations: readOnly("Get Signet JWKS"),
	}, d.getJWKS)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "signet_health",
		Description: "Fetch the Signet /health endpoint: overall status, dependency probes and feature flags.",
		Annotations: readOnly("Get Signet health"),
	}, d.health)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_decode_jwt",
		Description: "Decode a Signet JWT locally and verify its signature offline against the issuer's JWKS. " +
			"Checks iss, exp, nbf, aud and the Signet `type` claim one by one and explains every failure " +
			"(e.g. a refresh token being used where an access token is required). The token never leaves this machine.",
		Annotations: readOnly("Decode and verify a JWT"),
	}, d.decodeJWT)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_tokeninfo",
		Description: "Validate an access token online via Signet's GET /oauth/tokeninfo. " +
			"Rejects tokens whose `type` claim is not \"access\" (e.g. refresh tokens) with an explanation.",
		Annotations: readOnly("Validate access token online"),
	}, d.tokeninfo)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_introspect_token",
		Description: "Introspect a token via RFC 7662 POST /oauth/introspect. Requires OAuth client credentials " +
			"(falls back to the configured defaults) and returns the full token metadata.",
		Annotations: readOnly("Introspect token (RFC 7662)"),
	}, d.introspectToken)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "signet_userinfo",
		Description: "Fetch the OIDC UserInfo claims for an access token via GET /oauth/userinfo.",
		Annotations: readOnly("Get OIDC UserInfo"),
	}, d.userinfo)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_validate_cimd",
		Description: "Fetch a Client ID Metadata Document (CIMD) URL and validate it against the " +
			"draft-ietf-oauth-client-id-metadata-document / MCP 2026-07-28 rules: https URL without fragment, " +
			"client_id matching the URL, no client_secret, secretless auth method, valid redirect_uris.",
		Annotations: readOnly("Validate a CIMD document"),
	}, d.validateCIMD)

	mcp.AddTool(s, &mcp.Tool{
		Name: "signet_revoke_token",
		Description: "Revoke a token via RFC 7009 POST /oauth/revoke. Signet's revocation endpoint requires no " +
			"client authentication. Per RFC 7009 the server returns success even for already-invalid tokens, " +
			"so revoking twice is harmless.",
		Annotations: write("Revoke a token (RFC 7009)", true),
	}, d.revokeToken)
}

// --- 1. signet_get_metadata ---------------------------------------------

type getMetadataOut struct {
	Issuer       string         `json:"issuer"                  jsonschema:"the issuer this MCP server is configured against"`
	ASMetadata   map[string]any `json:"as_metadata,omitempty"   jsonschema:"RFC 8414 oauth-authorization-server document"`
	OIDCMetadata map[string]any `json:"oidc_metadata,omitempty" jsonschema:"openid-configuration document"`
	Differences  []string       `json:"differences,omitempty"   jsonschema:"human-readable differences between the two documents"`
}

func (d *Deps) getMetadata(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ struct{},
) (*mcp.CallToolResult, getMetadataOut, error) {
	out := getMetadataOut{Issuer: d.API.Issuer()}
	asMeta, asErr := d.API.WellKnownASMetadata(ctx)
	oidcMeta, oidcErr := d.API.WellKnownOIDC(ctx)
	if asErr != nil && oidcErr != nil {
		return nil, out, fmt.Errorf(
			"neither well-known document could be fetched: RFC 8414: %v; OIDC: %v",
			asErr,
			oidcErr,
		)
	}
	out.ASMetadata = asMeta
	out.OIDCMetadata = oidcMeta
	switch {
	case asErr != nil:
		out.Differences = append(out.Differences,
			fmt.Sprintf("/.well-known/oauth-authorization-server could not be fetched: %v", asErr))
	case oidcErr != nil:
		out.Differences = append(out.Differences,
			fmt.Sprintf("/.well-known/openid-configuration could not be fetched: %v", oidcErr))
	default:
		out.Differences = diffMetadata(asMeta, oidcMeta)
	}
	return nil, out, nil
}

// diffMetadata reports keys present in only one document and keys whose
// values differ between the RFC 8414 and OIDC documents.
func diffMetadata(asMeta, oidcMeta map[string]any) []string {
	var diffs []string
	keys := map[string]bool{}
	for k := range asMeta {
		keys[k] = true
	}
	for k := range oidcMeta {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		av, aok := asMeta[k]
		ov, ook := oidcMeta[k]
		switch {
		case !aok:
			diffs = append(diffs, fmt.Sprintf("%q only in openid-configuration", k))
		case !ook:
			diffs = append(diffs, fmt.Sprintf("%q only in oauth-authorization-server", k))
		default:
			aj, _ := json.Marshal(av)
			oj, _ := json.Marshal(ov)
			if string(aj) != string(oj) {
				diffs = append(
					diffs,
					fmt.Sprintf(
						"%q differs: oauth-authorization-server=%s openid-configuration=%s",
						k,
						aj,
						oj,
					),
				)
			}
		}
	}
	return diffs
}

// --- 2. signet_get_jwks --------------------------------------------------

type getJWKSOut struct {
	JWKSURI string          `json:"jwks_uri"`
	Count   int             `json:"count"`
	Keys    []signetapi.JWK `json:"keys"`
}

func (d *Deps) getJWKS(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ struct{},
) (*mcp.CallToolResult, getJWKSOut, error) {
	uri, keys, err := d.API.JWKS(ctx)
	if err != nil {
		return nil, getJWKSOut{}, fmt.Errorf("fetching JWKS: %w", err)
	}
	return nil, getJWKSOut{JWKSURI: uri, Count: len(keys), Keys: keys}, nil
}

// --- 3. signet_health ----------------------------------------------------

type healthOut struct {
	StatusCode int            `json:"status_code"`
	Healthy    bool           `json:"healthy"     jsonschema:"true when the server answered with HTTP 2xx"`
	Body       map[string]any `json:"body"        jsonschema:"raw /health response including dependency probes and feature flags"`
}

func (d *Deps) health(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	_ struct{},
) (*mcp.CallToolResult, healthOut, error) {
	status, doc, err := d.API.Health(ctx)
	if err != nil {
		return nil, healthOut{}, fmt.Errorf("fetching /health: %w", err)
	}
	return nil, healthOut{
		StatusCode: status,
		Healthy:    status >= 200 && status < 300,
		Body:       doc,
	}, nil
}

// --- 4. signet_decode_jwt ------------------------------------------------

type decodeJWTIn struct {
	Token            string `json:"token"                       jsonschema:"the JWT to decode; it is processed locally and never sent to any server"`
	ExpectedAudience string `json:"expected_audience,omitempty" jsonschema:"if set, check that the aud claim contains this value (RFC 8707 audience binding)"`
}

// claimCheck is one named validation with its outcome.
type claimCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type decodeJWTOut struct {
	Header         map[string]any `json:"header"`
	Claims         map[string]any `json:"claims"`
	SignatureValid bool           `json:"signature_valid"`
	SignatureError string         `json:"signature_error,omitempty"`
	Checks         []claimCheck   `json:"checks"`
	Valid          bool           `json:"valid"                     jsonschema:"true when the signature and every claim check passed"`
	Summary        string         `json:"summary"`
}

func (d *Deps) decodeJWT(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in decodeJWTIn,
) (*mcp.CallToolResult, decodeJWTOut, error) {
	header, claims, err := decodeJWTParts(in.Token)
	if err != nil {
		return nil, decodeJWTOut{}, err
	}
	out := decodeJWTOut{Header: header, Claims: claims}

	// Offline signature verification via the issuer's JWKS. jwksauth also
	// re-checks iss/exp/nbf; a failure there means the token would be
	// rejected by any Signet resource server.
	if v, err := d.verifier(); err != nil {
		out.SignatureError = fmt.Sprintf("could not build JWKS verifier: %v", err)
	} else if _, err := v.Verify(ctx, in.Token); err != nil {
		out.SignatureError = err.Error()
	} else {
		out.SignatureValid = true
	}

	out.Checks = checkClaims(claims, d.API.Issuer(), in.ExpectedAudience)
	out.Valid = out.SignatureValid
	failed := []string{}
	for _, c := range out.Checks {
		if !c.OK {
			out.Valid = false
			failed = append(failed, c.Name)
		}
	}
	switch {
	case out.Valid:
		out.Summary = "token is a valid Signet access token for this issuer"
	case len(failed) > 0:
		out.Summary = "claim checks failed: " + strings.Join(failed, ", ")
	default:
		out.Summary = "signature verification failed: " + out.SignatureError
	}
	return nil, out, nil
}

// decodeJWTParts splits a compact JWT and base64url-decodes its header and
// payload without verifying the signature.
func decodeJWTParts(token string) (header, claims map[string]any, err error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT: expected 3 dot-separated segments, got %d "+
			"(opaque tokens such as sgk_ Personal API Keys cannot be decoded — use signet_introspect_token instead)", len(parts))
	}
	for i, name := range []string{"header", "payload"} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return nil, nil, fmt.Errorf("JWT %s is not valid base64url: %w", name, err)
		}
		doc := map[string]any{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, nil, fmt.Errorf("JWT %s is not valid JSON: %w", name, err)
		}
		if i == 0 {
			header = doc
		} else {
			claims = doc
		}
	}
	return header, claims, nil
}

// checkClaims runs the per-claim diagnostics on an (unverified) payload.
func checkClaims(claims map[string]any, issuer, expectedAud string) []claimCheck {
	var checks []claimCheck
	add := func(name string, ok bool, detail string) {
		checks = append(checks, claimCheck{Name: name, OK: ok, Detail: detail})
	}

	iss, _ := claims["iss"].(string)
	add("iss", iss == issuer, fmt.Sprintf("iss=%q, configured issuer=%q", iss, issuer))

	now := time.Now()
	if exp, ok := numClaim(claims, "exp"); ok {
		expAt := time.Unix(exp, 0)
		if now.After(expAt) {
			add(
				"exp",
				false,
				fmt.Sprintf(
					"token expired %s ago (exp=%s)",
					now.Sub(expAt).Round(time.Second),
					expAt.UTC().Format(time.RFC3339),
				),
			)
		} else {
			add(
				"exp",
				true,
				fmt.Sprintf(
					"expires in %s (exp=%s)",
					time.Until(expAt).Round(time.Second),
					expAt.UTC().Format(time.RFC3339),
				),
			)
		}
	} else {
		add("exp", false, "no exp claim")
	}
	if nbf, ok := numClaim(claims, "nbf"); ok {
		nbfAt := time.Unix(nbf, 0)
		add(
			"nbf",
			!now.Before(nbfAt),
			"not valid before "+nbfAt.UTC().Format(time.RFC3339),
		)
	}

	auds := audClaim(claims)
	if expectedAud != "" {
		found := slices.Contains(auds, expectedAud)
		add(
			"aud",
			found,
			fmt.Sprintf(
				"aud=%v, expected to contain %q — a missing audience means the token was not "+
					"minted for that resource (RFC 8707); request it with the matching resource parameter",
				auds,
				expectedAud,
			),
		)
	} else {
		add(
			"aud",
			true,
			fmt.Sprintf("aud=%v (pass expected_audience to assert RFC 8707 binding)", auds),
		)
	}

	typ, _ := claims["type"].(string)
	switch typ {
	case "access":
		add("type", true, `type="access"`)
	case "refresh":
		add(
			"type",
			false,
			`type="refresh" — this is a refresh token, not an access token; it cannot be used as a `+
				`Bearer credential and Signet endpoints such as tokeninfo will reject it`,
		)
	case "":
		add("type", false, "no type claim — Signet access tokens carry type=\"access\"; "+
			"this may be an ID token or a JWT from another issuer")
	default:
		add(
			"type",
			false,
			fmt.Sprintf(
				"type=%q — not an access token; resource servers require type=\"access\"",
				typ,
			),
		)
	}
	return checks
}

// numClaim reads a numeric claim (JSON numbers decode as float64).
func numClaim(claims map[string]any, key string) (int64, bool) {
	f, ok := claims[key].(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

// audClaim normalizes the aud claim, which may be a string or an array.
func audClaim(claims map[string]any) []string {
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// --- 5. signet_tokeninfo -------------------------------------------------

type tokeninfoIn struct {
	AccessToken string `json:"access_token" jsonschema:"the access token to validate online"`
}

type tokeninfoOut struct {
	Active      bool   `json:"active"`
	UserID      string `json:"user_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Exp         int64  `json:"exp,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"   jsonschema:"RFC 3339 rendering of exp"`
	Iss         string `json:"iss,omitempty"`
	SubjectType string `json:"subject_type,omitempty"`
}

func (d *Deps) tokeninfo(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in tokeninfoIn,
) (*mcp.CallToolResult, tokeninfoOut, error) {
	oc, err := d.API.OAuth(ctx, "signet-mcp", "")
	if err != nil {
		return nil, tokeninfoOut{}, err
	}
	info, err := oc.TokenInfoRequest(ctx, in.AccessToken)
	if err != nil {
		return nil, tokeninfoOut{}, explainTokeninfoError(err)
	}
	out := tokeninfoOut{
		Active: info.Active, UserID: info.UserID, ClientID: info.ClientID,
		Scope: info.Scope, Exp: info.Exp, Iss: info.Iss, SubjectType: info.SubjectType,
	}
	if info.Exp > 0 {
		out.ExpiresAt = time.Unix(info.Exp, 0).UTC().Format(time.RFC3339)
	}
	return nil, out, nil
}

// explainTokeninfoError adds the type=="access" context that tokeninfo
// failures usually come down to.
func explainTokeninfoError(err error) error {
	translated := explainOAuthError("tokeninfo", err)
	return fmt.Errorf(
		"%w. Note: Signet's tokeninfo endpoint only accepts access tokens (JWT claim type == \"access\") — "+
			"refresh tokens and ID tokens are rejected; run signet_decode_jwt on the token to see its type claim",
		translated,
	)
}

// --- 6. signet_introspect_token -----------------------------------------

type introspectIn struct {
	Token         string `json:"token"                     jsonschema:"the token to introspect (access or refresh)"`
	TokenTypeHint string `json:"token_type_hint,omitempty" jsonschema:"optional RFC 7662 hint: access_token or refresh_token"`
	ClientID      string `json:"client_id,omitempty"       jsonschema:"OAuth client_id; defaults to the configured client"`
	ClientSecret  string `json:"client_secret,omitempty"   jsonschema:"OAuth client_secret for the given client_id"`
}

type introspectOut struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

func (d *Deps) introspectToken(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in introspectIn,
) (*mcp.CallToolResult, introspectOut, error) {
	clientID, clientSecret := d.clientCreds(in.ClientID, in.ClientSecret)
	if clientID == "" {
		return nil, introspectOut{}, errors.New(
			"introspection requires client credentials: pass client_id/client_secret " +
				"or start signet-mcp with --client-id/--client-secret",
		)
	}
	eps, err := d.API.Endpoints(ctx)
	if err != nil {
		return nil, introspectOut{}, err
	}
	form := url.Values{}
	form.Set("token", in.Token)
	if in.TokenTypeHint != "" {
		form.Set("token_type_hint", in.TokenTypeHint)
	}
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	out := introspectOut{}
	if err := d.API.PostForm(ctx, eps.IntrospectionURL, form, &out); err != nil {
		return nil, introspectOut{}, explainOAuthError("token introspection", err)
	}
	if out.Exp > 0 {
		out.ExpiresAt = time.Unix(out.Exp, 0).UTC().Format(time.RFC3339)
	}
	return nil, out, nil
}

// --- 7. signet_userinfo --------------------------------------------------

type userinfoIn struct {
	AccessToken string `json:"access_token" jsonschema:"access token with permission to read the user's claims"`
}

type userinfoOut struct {
	Sub               string `json:"sub"`
	Iss               string `json:"iss,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	SubjectType       string `json:"subject_type,omitempty"`
}

func (d *Deps) userinfo(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in userinfoIn,
) (*mcp.CallToolResult, userinfoOut, error) {
	oc, err := d.API.OAuth(ctx, "signet-mcp", "")
	if err != nil {
		return nil, userinfoOut{}, err
	}
	ui, err := oc.UserInfo(ctx, in.AccessToken)
	if err != nil {
		return nil, userinfoOut{}, explainOAuthError("userinfo", err)
	}
	return nil, userinfoOut{
		Sub: ui.Sub, Iss: ui.Iss, Name: ui.Name, PreferredUsername: ui.PreferredUsername,
		Email: ui.Email, EmailVerified: ui.EmailVerified, Picture: ui.Picture,
		UpdatedAt: ui.UpdatedAt, SubjectType: ui.SubjectType,
	}, nil
}

// --- 9. signet_revoke_token ---------------------------------------------

type revokeIn struct {
	Token         string `json:"token"                     jsonschema:"the token to revoke (access or refresh)"`
	TokenTypeHint string `json:"token_type_hint,omitempty" jsonschema:"optional RFC 7009 hint: access_token or refresh_token (Signet accepts and ignores it)"`
}

type revokeOut struct {
	Revoked bool   `json:"revoked"`
	Note    string `json:"note"`
}

func (d *Deps) revokeToken(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in revokeIn,
) (*mcp.CallToolResult, revokeOut, error) {
	eps, err := d.API.Endpoints(ctx)
	if err != nil {
		return nil, revokeOut{}, err
	}
	form := url.Values{}
	form.Set("token", in.Token)
	if in.TokenTypeHint != "" {
		form.Set("token_type_hint", in.TokenTypeHint)
	}
	if err := d.API.PostForm(ctx, eps.RevocationURL, form, nil); err != nil {
		return nil, revokeOut{}, explainOAuthError("token revocation", err)
	}
	return nil, revokeOut{
		Revoked: true,
		Note: "Signet accepted the revocation request. Per RFC 7009 the server also answers 200 for tokens " +
			"that were already invalid, so use signet_tokeninfo or signet_introspect_token to confirm the state.",
	}, nil
}
