package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxCIMDBytes matches Signet's own document size cap.
const maxCIMDBytes = 64 << 10 // 64 KiB

type validateCIMDIn struct {
	URL string `json:"url" jsonschema:"the client_id URL of the Client ID Metadata Document to fetch and validate"`
}

type validateCIMDOut struct {
	Valid    bool           `json:"valid"              jsonschema:"true when no error-level check failed"`
	Checks   []claimCheck   `json:"checks"`
	Warnings []string       `json:"warnings,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty" jsonschema:"the fetched document"`
}

// validateCIMD fetches and validates a Client ID Metadata Document per
// draft-ietf-oauth-client-id-metadata-document and the MCP 2026-07-28
// authorization spec, applying the same rules Signet enforces server-side.
func (d *Deps) validateCIMD(
	ctx context.Context,
	_ *mcp.CallToolRequest,
	in validateCIMDIn,
) (*mcp.CallToolResult, validateCIMDOut, error) {
	out := validateCIMDOut{}
	add := func(name string, ok bool, detail string) {
		out.Checks = append(out.Checks, claimCheck{Name: name, OK: ok, Detail: detail})
	}

	u, err := url.Parse(in.URL)
	if err != nil {
		return nil, out, fmt.Errorf("CIMD URL does not parse: %w", err)
	}
	add("url_scheme", strings.EqualFold(u.Scheme, "https"),
		fmt.Sprintf("scheme is %q; a CIMD client_id must use https", u.Scheme))
	add("url_host", u.Host != "", "URL must have a non-empty host")
	add("url_path", u.Path != "" && u.Path != "/",
		fmt.Sprintf("path is %q; a CIMD client_id must have a path (not the bare origin)", u.Path))
	add(
		"url_no_dot_segments",
		!strings.Contains(u.Path, "/../") && !strings.Contains(u.Path, "/./") &&
			!strings.HasSuffix(u.Path, "/..") && !strings.HasSuffix(u.Path, "/."),
		"path must not contain dot segments",
	)
	add(
		"url_no_fragment",
		u.Fragment == "" && !strings.Contains(in.URL, "#"),
		"URL must not contain a fragment",
	)
	add("url_no_userinfo", u.User == nil, "URL must not contain userinfo (user:password@)")

	doc, fetchChecks, err := fetchCIMD(ctx, d.cimdHTTP, in.URL)
	out.Checks = append(out.Checks, fetchChecks...)
	if err != nil {
		out.Valid = false
		return nil, out, nil //nolint:nilerr // the failure is reported through Checks
	}
	out.Metadata = doc

	clientID, _ := doc["client_id"].(string)
	add(
		"client_id_matches_url",
		clientID == in.URL,
		fmt.Sprintf(
			"document client_id is %q; it must byte-exactly equal the URL it was fetched from (%q)",
			clientID,
			in.URL,
		),
	)

	_, hasSecret := doc["client_secret"]
	add("no_client_secret", !hasSecret, "a CIMD document must not contain a client_secret")

	authMethod, _ := doc["token_endpoint_auth_method"].(string)
	add(
		"token_endpoint_auth_method",
		authMethod == "" || authMethod == "none",
		fmt.Sprintf(
			"token_endpoint_auth_method is %q; CIMD clients are public, so it must be absent or \"none\"",
			authMethod,
		),
	)

	redirectURIs, _ := doc["redirect_uris"].([]any)
	add(
		"redirect_uris_present",
		len(redirectURIs) > 0,
		"redirect_uris is required and must be non-empty",
	)
	if n := len(redirectURIs); n > 10 {
		add(
			"redirect_uris_count",
			false,
			fmt.Sprintf("%d redirect_uris; Signet caps the list at 10", n),
		)
	}
	for i, r := range redirectURIs {
		s, _ := r.(string)
		ru, err := url.Parse(s)
		ok := err == nil && ru.IsAbs() && ru.Host != ""
		if !ok {
			add(
				fmt.Sprintf("redirect_uri[%d]", i),
				false,
				fmt.Sprintf("%q is not an absolute URL with a host", s),
			)
		} else if ru.Scheme == "http" && ru.Hostname() != "localhost" && ru.Hostname() != "127.0.0.1" && ru.Hostname() != "::1" {
			out.Warnings = append(
				out.Warnings,
				fmt.Sprintf(
					"redirect_uri[%d] %q uses plain http on a non-loopback host; strict servers reject this",
					i,
					s,
				),
			)
		}
	}

	if gt, ok := doc["grant_types"].([]any); ok {
		found := false
		for _, g := range gt {
			if g == "authorization_code" {
				found = true
				break
			}
		}
		add(
			"grant_types",
			found,
			"when grant_types is present it must contain \"authorization_code\"",
		)
	}
	if _, ok := doc["client_name"]; !ok {
		out.Warnings = append(
			out.Warnings,
			"no client_name; note Signet shows the client_id host on the consent page, not the self-asserted name",
		)
	}

	out.Valid = true
	for _, c := range out.Checks {
		if !c.OK {
			out.Valid = false
			break
		}
	}
	return nil, out, nil
}

// fetchCIMD retrieves the document without following redirects and enforces
// the 64 KiB cap. A non-JSON Content-Type is recorded as a failing check —
// which makes the overall result invalid — but parsing still continues so the
// tool can report every other problem with the document in one pass; this is
// a diagnostics tool, not a gatekeeper (Signet itself performs the
// authoritative enforcement at /authorize time).
func fetchCIMD(
	ctx context.Context,
	httpc *http.Client,
	rawURL string,
) (map[string]any, []claimCheck, error) {
	var checks []claimCheck
	add := func(name string, ok bool, detail string) {
		checks = append(checks, claimCheck{Name: name, OK: ok, Detail: detail})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		add("fetch", false, err.Error())
		return nil, checks, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		add("fetch", false, fmt.Sprintf("GET failed: %v", err))
		return nil, checks, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf(
			"expected HTTP 200, got %d (redirects are not followed, matching Signet's fetcher)",
			resp.StatusCode,
		)
		add("fetch_status", false, err.Error())
		return nil, checks, err
	}
	add("fetch_status", true, "HTTP 200")
	ct := resp.Header.Get("Content-Type")
	add("content_type", strings.HasPrefix(ct, "application/json"),
		fmt.Sprintf("Content-Type is %q; expected application/json", ct))

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBytes+1))
	if err != nil {
		add("fetch_body", false, err.Error())
		return nil, checks, err
	}
	if len(body) > maxCIMDBytes {
		err := errors.New("document exceeds the 64 KiB cap Signet enforces")
		add("size", false, err.Error())
		return nil, checks, err
	}
	add("size", true, fmt.Sprintf("%d bytes (cap 64 KiB)", len(body)))
	doc := map[string]any{}
	if err := json.Unmarshal(body, &doc); err != nil {
		add("json", false, fmt.Sprintf("body is not valid JSON: %v", err))
		return nil, checks, err
	}
	add("json", true, "body parses as a JSON object")
	return doc, checks, nil
}
