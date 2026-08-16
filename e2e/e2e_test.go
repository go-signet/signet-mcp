// Package e2e runs the signet-mcp verification suite against a real Signet
// server on a local SQLite database.
//
// The suite is opt-in: set SIGNET_E2E=1 and have the signet source checked
// out next to this repo (or point SIGNET_SRC at it). Everything — the signet
// binary, its database, and the signet-mcp binary under test — is built into
// a temporary directory and torn down afterwards.
package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	jwtSecret     = "e2e-jwt-secret-0123456789abcdef0123456789abcdef"
	sessionSecret = "e2e-session-secret-0123456789abcdef01234567"
)

var (
	issuer       string
	clientID     string
	clientSecret string
	mcpBin       string
)

func TestMain(m *testing.M) {
	if os.Getenv("SIGNET_E2E") != "1" {
		// Tests skip themselves individually so `go test ./...` stays green.
		os.Exit(m.Run())
	}
	code, err := setupAndRun(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func setupAndRun(m *testing.M) (int, error) {
	signetSrc := os.Getenv("SIGNET_SRC")
	if signetSrc == "" {
		signetSrc = "../../signet"
	}
	if _, err := os.Stat(signetSrc); err != nil {
		return 0, fmt.Errorf("signet source not found at %s (set SIGNET_SRC): %w", signetSrc, err)
	}
	dir, err := os.MkdirTemp("", "signet-e2e-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)

	signetBin := filepath.Join(dir, "signet")
	if out, err := command(
		"go",
		"build",
		"-o",
		signetBin,
		".",
	).withDir(signetSrc).
		run(); err != nil {
		return 0, fmt.Errorf("building signet: %v\n%s", err, out)
	}
	mcpBin = filepath.Join(dir, "signet-mcp")
	if out, err := command("go", "build", "-o", mcpBin, ".").withDir("..").run(); err != nil {
		return 0, fmt.Errorf("building signet-mcp: %v\n%s", err, out)
	}

	port, err := freePort()
	if err != nil {
		return 0, err
	}
	issuer = fmt.Sprintf("http://localhost:%d", port)

	signet := exec.Command(signetBin, "server")
	signet.Dir = dir // signet-credentials.txt is written to the CWD
	signet.Env = append(os.Environ(),
		fmt.Sprintf("SERVER_ADDR=:%d", port),
		"BASE_URL="+issuer,
		"DATABASE_DRIVER=sqlite",
		"DATABASE_DSN="+filepath.Join(dir, "oauth.db"),
		"JWT_SECRET="+jwtSecret,
		"SESSION_SECRET="+sessionSecret,
		"ENVIRONMENT=development",
		"ENABLE_RATE_LIMIT=false",
		"DEFAULT_ADMIN_PASSWORD=e2e-admin-password-123",
		"LOG_LEVEL=warn",
	)
	signet.Stdout = os.Stderr
	signet.Stderr = os.Stderr
	if err := signet.Start(); err != nil {
		return 0, fmt.Errorf("starting signet: %w", err)
	}
	defer func() {
		_ = signet.Process.Kill()
		_ = signet.Wait()
	}()

	if err := waitHealthy(issuer + "/health"); err != nil {
		return 0, err
	}
	clientID, clientSecret, err = parseCredentials(filepath.Join(dir, "signet-credentials.txt"))
	if err != nil {
		return 0, err
	}
	return m.Run(), nil
}

type cmd struct{ c *exec.Cmd }

func command(name string, args ...string) cmd { return cmd{exec.Command(name, args...)} }
func (c cmd) withDir(dir string) cmd          { c.c.Dir = dir; return c }

func (c cmd) run() (string, error) { out, err := c.c.CombinedOutput(); return string(out), err }

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitHealthy(url string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec,noctx // local test URL
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("signet did not become healthy at %s", url)
}

// parseCredentials reads the bootstrap client from signet-credentials.txt.
func parseCredentials(path string) (id, secret string, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // test fixture path
	if err != nil {
		return "", "", fmt.Errorf("reading %s: %w", path, err)
	}
	for line := range strings.Lines(string(data)) {
		if v, ok := strings.CutPrefix(line, "Client ID:"); ok {
			id = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Client Secret:"); ok {
			secret = strings.TrimSpace(v)
		}
	}
	if id == "" {
		return "", "", fmt.Errorf("no Client ID in %s", path)
	}
	return id, secret, nil
}

// connect launches signet-mcp on stdio and returns a connected MCP session.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	if os.Getenv("SIGNET_E2E") != "1" {
		t.Skip("set SIGNET_E2E=1 to run the e2e suite against a local Signet")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "test"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	session, err := client.Connect(ctx, &mcp.CommandTransport{
		Command: exec.Command(mcpBin, "--issuer", issuer, "--client-id", clientID),
	}, nil)
	if err != nil {
		t.Fatalf("connecting to signet-mcp: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTool(
	t *testing.T,
	session *mcp.ClientSession,
	name string,
	args map[string]any,
) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("structured content is not an object: %v", err)
	}
	return doc
}

// TestHappyPath fetches the metadata and starts a device flow (verification
// scenario 1 from the plan).
func TestHappyPath(t *testing.T) {
	session := connect(t)

	res := callTool(t, session, "signet_get_metadata", map[string]any{})
	if res.IsError {
		t.Fatalf("signet_get_metadata errored: %s", resultText(res))
	}
	if got := structured(t, res)["issuer"]; got != issuer {
		t.Errorf("issuer = %v, want %s", got, issuer)
	}

	res = callTool(t, session, "signet_device_flow_start", map[string]any{})
	if res.IsError {
		t.Fatalf("signet_device_flow_start errored: %s", resultText(res))
	}
	out := structured(t, res)
	userCode, _ := out["user_code"].(string)
	verificationURI, _ := out["verification_uri"].(string)
	if userCode == "" || verificationURI == "" {
		t.Errorf("device flow start missing user_code/verification_uri: %v", out)
	}
}

// TestTokeninfoRejectsRefreshToken feeds a validly signed refresh token to
// signet_tokeninfo and expects a readable error that explains the
// type != "access" rejection (verification scenario 2).
func TestTokeninfoRejectsRefreshToken(t *testing.T) {
	session := connect(t)
	now := time.Now()
	refreshJWT := signHS256(t, map[string]any{
		"iss":       issuer,
		"sub":       "e2e-user",
		"client_id": clientID,
		"type":      "refresh",
		"jti":       "e2e-refresh-1",
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})

	res := callTool(t, session, "signet_tokeninfo", map[string]any{"access_token": refreshJWT})
	if !res.IsError {
		t.Fatalf("signet_tokeninfo should reject a refresh token, got: %s", resultText(res))
	}
	text := resultText(res)
	if !strings.Contains(text, `type == "access"`) {
		t.Errorf("error should explain the type != \"access\" rejection, got: %s", text)
	}
	if !strings.Contains(text, "invalid_token") {
		t.Errorf("error should surface Signet's invalid_token code, got: %s", text)
	}
}

// TestIntrospectWrongCredentials introspects with a bad client secret and
// expects a readable invalid_client translation that does not leak the
// credentials (verification scenario 3).
func TestIntrospectWrongCredentials(t *testing.T) {
	session := connect(t)
	const wrongSecret = "definitely-not-the-secret"

	res := callTool(t, session, "signet_introspect_token", map[string]any{
		"token":         "some-opaque-token",
		"client_id":     clientID,
		"client_secret": wrongSecret,
	})
	if !res.IsError {
		t.Fatalf("introspection with wrong credentials should fail, got: %s", resultText(res))
	}
	text := resultText(res)
	if !strings.Contains(text, "invalid_client") {
		t.Errorf("error should carry the invalid_client code, got: %s", text)
	}
	if !strings.Contains(text, "client authentication failed") {
		t.Errorf("error should include the readable hint, got: %s", text)
	}
	if strings.Contains(text, wrongSecret) ||
		(clientSecret != "" && strings.Contains(text, clientSecret)) {
		t.Errorf("error must not leak client credentials: %s", text)
	}
}

// signHS256 mints a compact JWT with the e2e Signet's HS256 secret.
func signHS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
