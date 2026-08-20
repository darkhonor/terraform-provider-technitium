// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestServer creates a mock Technitium API server.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

func TestNewClient_ValidInputs(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380", Token: "test-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "http://localhost:5380" {
		t.Errorf("expected baseURL http://localhost:5380, got %s", c.baseURL)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380/", Token: "test-token"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "http://localhost:5380" {
		t.Errorf("expected trailing slash stripped, got %s", c.baseURL)
	}
}

func TestNewClient_EmptyURL(t *testing.T) {
	_, err := NewClient(ClientConfig{BaseURL: "", Token: "test-token"})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestNewClient_EmptyToken(t *testing.T) {
	_, err := NewClient(ClientConfig{BaseURL: "http://localhost:5380", Token: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNewClient_SkipTLSVerify(t *testing.T) {
	c, err := NewClient(ClientConfig{BaseURL: "https://localhost:5380", Token: "test-token", SkipTLSVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestZoneCreate_ForwarderCreatesEmptyZone(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/zones/create" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("zone") != "." || q.Get("type") != "Forwarder" {
			t.Fatalf("unexpected create query: %s", r.URL.RawQuery)
		}
		if q.Get("initializeForwarder") != "false" {
			t.Fatalf("Forwarder zone should be created empty with initializeForwarder=false, got query: %s", r.URL.RawQuery)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"domain":"."}`),
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	domain, err := c.ZoneCreate(context.Background(), ".", "Forwarder", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if domain != "." {
		t.Fatalf("domain = %q, want .", domain)
	}
}

func TestDoGet_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization: Bearer test-token, got %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Has("token") {
			t.Error("token must not be passed in query params by default")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"zones":[]}`),
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	resp, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

// TestDoGet_TokenViaBearerHeader is a regression test for the default
// authentication mode: the token must reach the server as an Authorization
// header, and the request URL must carry no "token" query parameter at all
// (not even an empty one), since any intermediary logging the URL would
// otherwise still capture the token shape or value.
func TestDoGet_TokenViaBearerHeader(t *testing.T) {
	var gotAuthHeader string
	var gotRawQuery string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotRawQuery = r.URL.RawQuery
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "super-secret-token"})
	params := url.Values{"zone": {"example.com"}}
	if _, err := c.doGet(context.Background(), "/api/zones/options/get", params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuthHeader != "Bearer super-secret-token" {
		t.Errorf("expected Authorization: Bearer super-secret-token, got %q", gotAuthHeader)
	}
	if strings.Contains(gotRawQuery, "token") {
		t.Errorf("expected no token in query string, got %q", gotRawQuery)
	}
}

// TestDoGet_LegacyTokenAuth verifies that setting LegacyTokenAuth preserves
// the pre-15.0 behavior of sending the token as a query parameter, for
// operators on older Technitium DNS Server versions that don't understand
// the Authorization header.
func TestDoGet_LegacyTokenAuth(t *testing.T) {
	var gotAuthHeader string
	var gotToken string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotToken = r.URL.Query().Get("token")
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "legacy-token", LegacyTokenAuth: true})
	if _, err := c.doGet(context.Background(), "/api/zones/list", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotToken != "legacy-token" {
		t.Errorf("expected token=legacy-token in query params, got %q", gotToken)
	}
	if gotAuthHeader != "" {
		t.Errorf("expected no Authorization header in legacy mode, got %q", gotAuthHeader)
	}
}

// TestDoGet_LegacyTokenAuth_TransportErrorRedactsToken is a regression test
// for a token leak via *url.Error: in LegacyTokenAuth mode the token
// travels in the request's query string, and http.Client.Do wraps
// transport failures (DNS, connection refused, TLS, timeout...) in a
// *url.Error whose Error() method embeds the full request URL verbatim,
// including that query string. Without redaction, the token would land in
// the Terraform diagnostic surfaced to the user (see provider.go's
// "Unable to connect to Technitium server" diagnostic).
func TestDoGet_LegacyTokenAuth_TransportErrorRedactsToken(t *testing.T) {
	const secretToken = "super-secret-token-abc123"

	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	ts.Close() // closed immediately: any request now fails at the transport layer

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: secretToken, LegacyTokenAuth: true})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Errorf("error message leaks the API token: %v", err)
	}
}

// TestPing_LegacyTokenAuth_TransportErrorRedactsToken covers the exact call
// path the provider's connectivity check uses (provider.go calls
// apiClient.Ping, then surfaces err.Error() verbatim in a diagnostic when
// the failure isn't classified as TLS-related).
func TestPing_LegacyTokenAuth_TransportErrorRedactsToken(t *testing.T) {
	const secretToken = "super-secret-ping-token"

	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: secretToken, LegacyTokenAuth: true})
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Errorf("error message leaks the API token: %v", err)
	}
}

func TestDoGet_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "zone not found",
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet(context.Background(), "/api/zones/options/get", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.ErrorMessage != "zone not found" {
		t.Errorf("expected 'zone not found', got %s", apiErr.ErrorMessage)
	}
}

func TestDoGet_InvalidToken(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "invalid-token",
			ErrorMessage: "The session has expired. Please login again.",
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "bad-token"})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if !apiErr.IsInvalidToken() {
		t.Error("expected IsInvalidToken() to be true")
	}
}

func TestDoGet_HTTPError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("internal server error")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestDoGet_InvalidJSON(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte("not json")); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doGet(context.Background(), "/api/zones/list", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDoPost_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Authorization: Bearer test-token, got %q", r.Header.Get("Authorization"))
		}
		if r.FormValue("token") != "" {
			t.Error("token must not be passed in form body by default")
		}
		if r.FormValue("setting") != "value1" {
			t.Error("expected setting=value1 in form body")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	params := url.Values{"setting": {"value1"}}
	resp, err := c.doPost(context.Background(), "/api/settings/set", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

// TestDoPost_LegacyTokenAuth verifies that setting LegacyTokenAuth preserves
// the pre-15.0 behavior of sending the token as a form field.
func TestDoPost_LegacyTokenAuth(t *testing.T) {
	var gotAuthHeader string
	var gotToken string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotToken = r.FormValue("token")
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "legacy-token", LegacyTokenAuth: true})
	if _, err := c.doPost(context.Background(), "/api/settings/set", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotToken != "legacy-token" {
		t.Errorf("expected token=legacy-token in form body, got %q", gotToken)
	}
	if gotAuthHeader != "" {
		t.Errorf("expected no Authorization header in legacy mode, got %q", gotAuthHeader)
	}
}

func TestDoPost_APIError(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "access denied",
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.doPost(context.Background(), "/api/settings/set", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPing_Success(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPing_InvalidToken(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "invalid-token",
			ErrorMessage: "Invalid token.",
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "bad-token"})
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// generateTestCACert creates a self-signed CA certificate for testing.
func generateTestCACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestNewClient_CACertFile_Valid(t *testing.T) {
	certPEM := generateTestCACert(t)
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(certPEM); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	c, err := NewClient(ClientConfig{
		BaseURL:    "https://localhost:5380",
		Token:      "test-token",
		CACertFile: f.Name(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestNewClient_CACertFile_NotFound(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:    "https://localhost:5380",
		Token:      "test-token",
		CACertFile: "/nonexistent/path/ca.pem",
	})
	if err == nil {
		t.Fatal("expected error for missing CA cert file")
	}
	if !strings.Contains(err.Error(), "CA certificate file not found") {
		t.Errorf("expected 'CA certificate file not found' in error, got: %v", err)
	}
}

func TestNewClient_CACertFile_InvalidPEM(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("this is not valid PEM data"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	_, err = NewClient(ClientConfig{
		BaseURL:    "https://localhost:5380",
		Token:      "test-token",
		CACertFile: f.Name(),
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "failed to parse CA certificate") {
		t.Errorf("expected 'failed to parse CA certificate' in error, got: %v", err)
	}
}

func TestNewClient_CACertDir_Valid(t *testing.T) {
	dir := t.TempDir()
	certPEM := generateTestCACert(t)
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientConfig{
		BaseURL:   "https://localhost:5380",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestNewClient_CACertDir_NotFound(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:   "https://localhost:5380",
		Token:     "test-token",
		CACertDir: "/nonexistent/directory/path",
	})
	if err == nil {
		t.Fatal("expected error for missing CA cert directory")
	}
	if !strings.Contains(err.Error(), "CA certificate directory not found") {
		t.Errorf("expected 'CA certificate directory not found' in error, got: %v", err)
	}
}

func TestNewClient_CACertDir_Empty(t *testing.T) {
	dir := t.TempDir()

	_, err := NewClient(ClientConfig{
		BaseURL:   "https://localhost:5380",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err == nil {
		t.Fatal("expected error for empty CA cert directory")
	}
	if !strings.Contains(err.Error(), "no valid PEM certificates found") {
		t.Errorf("expected 'no valid PEM certificates found' in error, got: %v", err)
	}
}

func TestNewClient_CACertDir_SkipsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	certPEM := generateTestCACert(t)
	if err := os.WriteFile(filepath.Join(dir, "valid-ca.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.pem"), []byte("not valid PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientConfig{
		BaseURL:   "https://localhost:5380",
		Token:     "test-token",
		CACertDir: dir,
	})
	if err != nil {
		t.Fatalf("unexpected error (should skip invalid files): %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set from valid file")
	}
}

func TestNewClient_CACertFileAndDir_Combined(t *testing.T) {
	dir := t.TempDir()
	certPEM1 := generateTestCACert(t)
	certPEM2 := generateTestCACert(t)

	f, err := os.CreateTemp(t.TempDir(), "ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(certPEM1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if err := os.WriteFile(filepath.Join(dir, "ca2.pem"), certPEM2, 0600); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientConfig{
		BaseURL:    "https://localhost:5380",
		Token:      "test-token",
		CACertFile: f.Name(),
		CACertDir:  dir,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set from both sources")
	}
}

func TestNewClient_HTTP_IgnoresTLSConfig(t *testing.T) {
	// http:// URLs should ignore CA cert paths entirely — no error even if paths are invalid
	c, err := NewClient(ClientConfig{
		BaseURL:    "http://localhost:5380",
		Token:      "test-token",
		CACertFile: "/nonexistent/ca.pem",
		CACertDir:  "/nonexistent/dir",
	})
	if err != nil {
		t.Fatalf("http URL should ignore invalid TLS config paths, got error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig != nil {
		t.Error("expected no TLSClientConfig for http URL")
	}
}

func TestNewClient_TLSServerName(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://localhost:5380",
		Token:         "test-token",
		TLSServerName: "my-dns-server.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if transport.TLSClientConfig.ServerName != "my-dns-server.example.com" {
		t.Errorf("expected ServerName 'my-dns-server.example.com', got %q", transport.TLSClientConfig.ServerName)
	}
}

func TestNewClient_TLSMinVersion13(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://localhost:5380",
		Token:         "test-token",
		TLSMinVersion: "1.3",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS 1.3, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestNewClient_TLSMinVersion12(t *testing.T) {
	c, err := NewClient(ClientConfig{
		BaseURL:       "https://localhost:5380",
		Token:         "test-token",
		TLSMinVersion: "1.2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", transport.TLSClientConfig.MinVersion)
	}
}

func TestNewClient_TLSMinVersionInvalid(t *testing.T) {
	_, err := NewClient(ClientConfig{
		BaseURL:       "https://localhost:5380",
		Token:         "test-token",
		TLSMinVersion: "1.1",
	})
	if err == nil {
		t.Fatal("expected error for invalid TLS min version")
	}
	if !strings.Contains(err.Error(), "invalid tls_min_version") {
		t.Errorf("expected 'invalid tls_min_version' in error, got: %v", err)
	}
}

func TestNewClient_TLSMinVersionDefault(t *testing.T) {
	// Empty TLSMinVersion should default to TLS 1.3
	c, err := NewClient(ClientConfig{
		BaseURL: "https://localhost:5380",
		Token:   "test-token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected default MinVersion TLS 1.3, got %d", transport.TLSClientConfig.MinVersion)
	}
}
