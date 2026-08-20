// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// APIResponse is the base response envelope from Technitium.
type APIResponse struct {
	Status            string          `json:"status"`
	ErrorMessage      string          `json:"errorMessage,omitempty"`
	InnerErrorMessage string          `json:"innerErrorMessage,omitempty"`
	Response          json.RawMessage `json:"response,omitempty"`
}

// APIError represents a non-OK response from the Technitium API.
type APIError struct {
	Status       string
	ErrorMessage string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("technitium API error (status=%s): %s", e.Status, e.ErrorMessage)
}

// IsInvalidToken returns true if the error indicates an expired or invalid token.
func (e *APIError) IsInvalidToken() bool {
	return e.Status == "invalid-token"
}

// ClientConfig holds all configuration options for NewClient.
type ClientConfig struct {
	BaseURL       string
	Token         string
	SkipTLSVerify bool // default: false
	CACertFile    string
	CACertDir     string
	TLSServerName string
	TLSMinVersion string // "1.2" or "1.3", default: "1.3"
	// LegacyTokenAuth sends the API token via the "token" query parameter
	// (GET) or form body (POST) instead of an "Authorization: Bearer"
	// header. Technitium DNS Server versions before 15.0 only understand
	// the query-string/form form; the header is otherwise preferred
	// because query strings are routinely captured in cleartext by
	// reverse-proxy access logs. Default: false.
	LegacyTokenAuth bool
}

// Client is the Technitium DNS Server API client.
type Client struct {
	baseURL         string
	token           string
	legacyTokenAuth bool
	httpClient      *http.Client
}

// NewClient creates a new Technitium API client.
func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("server_url must not be empty")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("api_token must not be empty")
	}
	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = "1.3"
	}

	transport := &http.Transport{}
	isHTTPS := strings.HasPrefix(cfg.BaseURL, "https://")

	if isHTTPS {
		tlsConfig := &tls.Config{} //nolint:gosec // MinVersion set below

		rootCAs, err := loadCACerts(cfg.CACertFile, cfg.CACertDir)
		if err != nil {
			return nil, err
		}
		if rootCAs != nil {
			tlsConfig.RootCAs = rootCAs
		}

		if cfg.TLSServerName != "" {
			tlsConfig.ServerName = cfg.TLSServerName
		}

		switch cfg.TLSMinVersion {
		case "1.3":
			tlsConfig.MinVersion = tls.VersionTLS13
		case "1.2":
			tlsConfig.MinVersion = tls.VersionTLS12
		default:
			return nil, fmt.Errorf("invalid tls_min_version %q: must be \"1.2\" or \"1.3\"", cfg.TLSMinVersion)
		}

		if cfg.SkipTLSVerify {
			tlsConfig.InsecureSkipVerify = true //nolint:gosec // User explicitly opted in
		}

		transport.TLSClientConfig = tlsConfig
	}

	return &Client{
		baseURL:         cfg.BaseURL,
		token:           cfg.Token,
		legacyTokenAuth: cfg.LegacyTokenAuth,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// loadCACerts loads PEM certificates from certFile and/or certDir into a new
// x509.CertPool. Returns nil (no error) if both paths are empty. Directory
// loading is non-recursive and skips files that contain no valid PEM certs
// (Vault convention). Returns an error if the pool would be empty and only a
// certDir was specified (certFile parse failures are always fatal).
func loadCACerts(certFile, certDir string) (*x509.CertPool, error) {
	if certFile == "" && certDir == "" {
		return nil, nil //nolint:nilnil // nil pool signals "use system CA defaults" to caller
	}
	pool := x509.NewCertPool()
	loaded := 0

	if certFile != "" {
		data, err := os.ReadFile(certFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("CA certificate file not found: %s", certFile)
			}
			return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("failed to parse CA certificate: %s", certFile)
		}
		loaded++
	}

	if certDir != "" {
		entries, err := os.ReadDir(certDir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("CA certificate directory not found: %s", certDir)
			}
			return nil, fmt.Errorf("failed to read CA certificate directory: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(certDir, entry.Name()))
			if err != nil {
				continue
			}
			if pool.AppendCertsFromPEM(data) {
				loaded++
			}
		}
	}

	if loaded == 0 && certDir != "" && certFile == "" {
		return nil, fmt.Errorf("no valid PEM certificates found in %s", certDir)
	}
	return pool, nil
}

// redactURL returns rawURL with its query string stripped. Use it wherever
// a request URL might end up in an error message: in LegacyTokenAuth mode
// the "token" query parameter carries the live API token, and query
// strings never carry anything of similarly sensitive shape in the default
// header-auth path, so stripping unconditionally is safe on both. If
// rawURL fails to parse, a fixed placeholder is returned rather than the
// unparsed (and therefore unredacted) string.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[redacted URL]"
	}
	u.RawQuery = ""
	return u.String()
}

// redactTransportErr converts an error returned by (*http.Client).Do into
// an error safe to surface to the user (e.g. via a Terraform diagnostic).
// http.Client.Do returns a *url.Error whose Error() method embeds the full
// request URL verbatim, including the query string — so wrapping it
// directly with %w would still render that URL (and, in LegacyTokenAuth
// mode, the API token it carries) whenever the resulting error's Error()
// is later called. This rebuilds the message from a query-stripped URL and
// wraps only the innermost cause, so errors.As-based classification (e.g.
// ClassifyTLSError) keeps working against the unwrapped chain.
func redactTransportErr(path string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s %s failed: %w", urlErr.Op, redactURL(urlErr.URL), urlErr.Err)
	}
	return fmt.Errorf("request to %s failed: %w", path, err)
}

// doGet performs a GET request to the Technitium API and returns the parsed response.
// Most Technitium API endpoints use GET with query parameters, including mutations.
//
// The API token is sent as an "Authorization: Bearer" header by default. Set
// LegacyTokenAuth on the client to fall back to the "token" query parameter
// for Technitium DNS Server versions before 15.0.
func (c *Client) doGet(ctx context.Context, path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	if c.legacyTokenAuth {
		params.Set("token", c.token)
	}

	reqURL := c.baseURL + path
	if encoded := params.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request to %s: %w", path, err)
	}
	if !c.legacyTokenAuth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, redactTransportErr(path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	return c.parseResponse(resp)
}

// doPost performs a POST request with form-encoded body (used by /api/settings/set).
//
// The API token is sent as an "Authorization: Bearer" header by default. Set
// LegacyTokenAuth on the client to fall back to the "token" form field for
// Technitium DNS Server versions before 15.0.
func (c *Client) doPost(ctx context.Context, path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	if c.legacyTokenAuth {
		params.Set("token", c.token)
	}

	reqURL := fmt.Sprintf("%s%s", c.baseURL, path)
	body := strings.NewReader(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request to %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !c.legacyTokenAuth {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, redactTransportErr(path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	return c.parseResponse(resp)
}

// parseResponse reads the response body and checks for API-level errors.
func (c *Client) parseResponse(resp *http.Response) (*APIResponse, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("decoding response JSON: %w", err)
	}

	if apiResp.Status != "ok" {
		return nil, &APIError{
			Status:       apiResp.Status,
			ErrorMessage: apiResp.ErrorMessage,
		}
	}

	return &apiResp, nil
}

// Ping verifies that the client can reach the server and the token is valid.
// Uses /api/user/session/get which exists across all Technitium versions and
// validates the token without side effects. Falls back to /api/settings/get
// if the session endpoint is unavailable.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.doGet(ctx, "/api/user/session/get", nil)
	if err != nil {
		// Fallback: try settings endpoint (always exists, requires valid token)
		_, err = c.doGet(ctx, "/api/settings/get", nil)
	}
	return err
}
