// Package signetapi is signet-mcp's thin client for a Signet server.
//
// It reuses the sdk-go packages (discovery, oauth) where they fit and adds
// the raw calls the diagnostics tools need: unfiltered well-known documents,
// JWKS listing, /health, and token-endpoint requests that carry the RFC 8707
// resource parameter (which the sdk-go oauth client does not expose).
package signetapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/oauth"
)

// maxResponseBytes bounds every response body we read from Signet.
const maxResponseBytes = 1 << 20 // 1 MiB

// Client talks to one Signet server.
type Client struct {
	issuer string
	http   *http.Client
	disc   *discovery.Client
}

// New builds a Client for the given issuer URL.
func New(issuer string, timeout time.Duration) (*Client, error) {
	disc, err := discovery.NewClient(issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery client: %w", err)
	}
	return &Client{
		issuer: strings.TrimRight(issuer, "/"),
		disc:   disc,
		http: &http.Client{
			Timeout: timeout,
			// OAuth responses and bearer credentials must never follow a
			// redirect to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Issuer returns the configured issuer URL (no trailing slash).
func (c *Client) Issuer() string { return c.issuer }

// Endpoints returns the discovered OAuth endpoints.
func (c *Client) Endpoints(ctx context.Context) (oauth.Endpoints, error) {
	md, err := c.disc.Fetch(ctx)
	if err != nil {
		return oauth.Endpoints{}, fmt.Errorf("OIDC discovery for %s: %w", c.issuer, err)
	}
	return md.Endpoints(), nil
}

// OAuth builds an sdk-go OAuth client bound to the discovered endpoints.
func (c *Client) OAuth(ctx context.Context, clientID, clientSecret string) (*oauth.Client, error) {
	eps, err := c.Endpoints(ctx)
	if err != nil {
		return nil, err
	}
	opts := []oauth.Option{}
	if clientSecret != "" {
		opts = append(opts, oauth.WithClientSecret(clientSecret))
	}
	oc, err := oauth.NewClient(clientID, eps, opts...)
	if err != nil {
		return nil, fmt.Errorf("oauth client: %w", err)
	}
	return oc, nil
}

// APIError is a non-2xx JSON response from Signet (RFC 6749 §5.2 shape).
type APIError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	StatusCode  int    `json:"-"`
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Description, e.StatusCode)
	}
	return fmt.Sprintf("%s (HTTP %d)", e.Code, e.StatusCode)
}

// GetJSON fetches an absolute or issuer-relative URL and decodes the JSON
// body into a map. Non-2xx responses yield an *APIError when the body is an
// OAuth-style error object.
func (c *Client) GetJSON(ctx context.Context, rawURL string) (map[string]any, error) {
	if strings.HasPrefix(rawURL, "/") {
		rawURL = c.issuer + rawURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if err := json.Unmarshal(body, &doc); err != nil {
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("GET %s: HTTP %d (non-JSON body)", rawURL, resp.StatusCode)
		}
		return nil, fmt.Errorf("GET %s: invalid JSON: %w", rawURL, err)
	}
	if resp.StatusCode >= 300 {
		if apiErr := asAPIError(doc, resp.StatusCode); apiErr != nil {
			return nil, apiErr
		}
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return doc, nil
}

// WellKnownASMetadata fetches /.well-known/oauth-authorization-server (RFC 8414).
func (c *Client) WellKnownASMetadata(ctx context.Context) (map[string]any, error) {
	return c.GetJSON(ctx, "/.well-known/oauth-authorization-server")
}

// WellKnownOIDC fetches /.well-known/openid-configuration.
func (c *Client) WellKnownOIDC(ctx context.Context) (map[string]any, error) {
	return c.GetJSON(ctx, "/.well-known/openid-configuration")
}

// JWK is one key from the JWKS document.
type JWK struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
}

// JWKS fetches the JWKS document. The URL comes from the OIDC discovery
// document's jwks_uri, falling back to /.well-known/jwks.json.
func (c *Client) JWKS(ctx context.Context) (jwksURI string, keys []JWK, err error) {
	jwksURI = c.issuer + "/.well-known/jwks.json"
	if oidc, err := c.WellKnownOIDC(ctx); err == nil {
		if u, ok := oidc["jwks_uri"].(string); ok && u != "" {
			jwksURI = u
		}
	}
	doc, err := c.GetJSON(ctx, jwksURI)
	if err != nil {
		return jwksURI, nil, err
	}
	rawKeys, err := json.Marshal(doc["keys"])
	if err != nil {
		return jwksURI, nil, err
	}
	if err := json.Unmarshal(rawKeys, &keys); err != nil {
		return jwksURI, nil, fmt.Errorf("unexpected JWKS shape at %s: %w", jwksURI, err)
	}
	return jwksURI, keys, nil
}

// Health fetches /health and reports the HTTP status alongside the body.
func (c *Client) Health(ctx context.Context) (status int, doc map[string]any, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/health", nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	doc = map[string]any{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return resp.StatusCode, nil, fmt.Errorf(
			"/health returned non-JSON body (HTTP %d)",
			resp.StatusCode,
		)
	}
	return resp.StatusCode, doc, nil
}

// TokenResponse is a raw RFC 6749 §5.1 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// PostForm sends a form-encoded POST to an endpoint and decodes the JSON
// response into out. Client credentials use client_secret_post (form body),
// matching sdk-go and Signet. OAuth error responses come back as *APIError.
func (c *Client) PostForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		doc := map[string]any{}
		if json.Unmarshal(body, &doc) == nil {
			if apiErr := asAPIError(doc, resp.StatusCode); apiErr != nil {
				return apiErr
			}
		}
		return fmt.Errorf("POST %s: HTTP %d", endpoint, resp.StatusCode)
	}
	// RFC 7009 revocation answers 200 with an empty body.
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("POST %s: invalid JSON response: %w", endpoint, err)
	}
	return nil
}

// TokenRequest posts to the token endpoint with the given grant parameters,
// adding client credentials and optional RFC 8707 resource values.
func (c *Client) TokenRequest(
	ctx context.Context, form url.Values, clientID, clientSecret string, resources []string,
) (*TokenResponse, error) {
	eps, err := c.Endpoints(ctx)
	if err != nil {
		return nil, err
	}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	for _, r := range resources {
		form.Add("resource", r)
	}
	tok := &TokenResponse{}
	if err := c.PostForm(ctx, eps.TokenURL, form, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// DeviceAuthResponse is an RFC 8628 §3.2 device authorization response.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// DeviceCodeRequest starts an RFC 8628 device authorization, optionally
// carrying RFC 8707 resource values.
func (c *Client) DeviceCodeRequest(
	ctx context.Context, clientID, clientSecret string, scopes, resources []string,
) (*DeviceAuthResponse, error) {
	eps, err := c.Endpoints(ctx)
	if err != nil {
		return nil, err
	}
	if eps.DeviceAuthorizationURL == "" {
		return nil, errors.New("issuer metadata advertises no device_authorization_endpoint")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	for _, r := range resources {
		form.Add("resource", r)
	}
	da := &DeviceAuthResponse{}
	if err := c.PostForm(ctx, eps.DeviceAuthorizationURL, form, da); err != nil {
		return nil, err
	}
	return da, nil
}

// asAPIError converts an OAuth-style error body into an *APIError, or nil if
// the document has no "error" member.
func asAPIError(doc map[string]any, status int) *APIError {
	code, ok := doc["error"].(string)
	if !ok || code == "" {
		return nil
	}
	desc, _ := doc["error_description"].(string)
	return &APIError{Code: code, Description: desc, StatusCode: status}
}
