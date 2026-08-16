package config

import (
	"strings"
	"testing"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]string{"--issuer", "https://auth.example.com/"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Issuer != "https://auth.example.com" {
		t.Errorf("issuer not normalized: %q", cfg.Issuer)
	}
	if cfg.Transport != TransportStdio {
		t.Errorf("default transport = %q, want stdio", cfg.Transport)
	}
	if len(cfg.Toolsets) != 2 || cfg.Toolsets[0] != ToolsetDiagnostics ||
		cfg.Toolsets[1] != ToolsetFlow {
		t.Errorf("default toolsets = %v", cfg.Toolsets)
	}
}

func TestParseMissingIssuer(t *testing.T) {
	if _, err := Parse(nil); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Errorf("want missing-issuer error, got %v", err)
	}
}

func TestParseUnknownToolset(t *testing.T) {
	_, err := Parse(
		[]string{"--issuer", "https://a.example.com", "--toolsets", "diagnostics,admin"},
	)
	if err == nil || !strings.Contains(err.Error(), "admin") {
		t.Errorf("want unknown-toolset error, got %v", err)
	}
}

func TestParseUnknownTransport(t *testing.T) {
	_, err := Parse([]string{"--issuer", "https://a.example.com", "--transport", "sse"})
	if err == nil || !strings.Contains(err.Error(), "transport") {
		t.Errorf("want invalid-transport error, got %v", err)
	}
}

func TestParseHTTPDefaultsPublicURL(t *testing.T) {
	cfg, err := Parse(
		[]string{
			"--issuer",
			"https://a.example.com",
			"--transport",
			"http",
			"--addr",
			"localhost:9999",
		},
	)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.PublicURL != "http://localhost:9999" {
		t.Errorf("PublicURL = %q", cfg.PublicURL)
	}
}
