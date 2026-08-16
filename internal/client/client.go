// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	BaseURL        string
	Token          string
	Username       string // used with Password when Token is empty
	Password       string
	SkipTLSVerify  bool // default: false
	CACertFile     string
	CACertDir      string
	TLSServerName  string
	TLSMinVersion  string // "1.2" or "1.3", default: "1.3"
	TimeoutSeconds int    // HTTP client timeout, default: 30
}

// Client is the Technitium DNS Server API client.
type Client struct {
	baseURL    string
	token      string
	username   string
	password   string
	httpClient *http.Client
}

// NewClient creates a new Technitium API client. Authentication is either a
// pre-existing API token, or a username/password pair — in the latter case
// Login must be called before any other API call to obtain a session token.
func NewClient(cfg ClientConfig) (*Client, error) {
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("server_url must not be empty")
	}
	if cfg.Token == "" && (cfg.Username == "" || cfg.Password == "") {
		return nil, fmt.Errorf("either api_token or username and password must be set")
	}
	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = "1.3"
	}
	if cfg.TimeoutSeconds <= 0 {
		cfg.TimeoutSeconds = 30
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
		baseURL:  cfg.BaseURL,
		token:    cfg.Token,
		username: cfg.Username,
		password: cfg.Password,
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport: transport,
		},
	}, nil
}

// Login authenticates with the configured username/password and stores the
// resulting session token for subsequent API calls. No-op requirement: the
// client must have been created with Username and Password set.
func (c *Client) Login(ctx context.Context) error {
	if c.username == "" || c.password == "" {
		return fmt.Errorf("login requires username and password")
	}

	params := url.Values{
		"user": {c.username},
		"pass": {c.password},
	}
	reqURL := fmt.Sprintf("%s/api/user/login", c.baseURL)
	body := strings.NewReader(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading login response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d on login: %s", resp.StatusCode, string(respBody))
	}

	// The login response carries the token at the top level, outside the
	// usual "response" envelope.
	var loginResp struct {
		Status       string `json:"status"`
		ErrorMessage string `json:"errorMessage"`
		Token        string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return fmt.Errorf("decoding login response JSON: %w", err)
	}
	if loginResp.Status != "ok" {
		return &APIError{Status: loginResp.Status, ErrorMessage: loginResp.ErrorMessage}
	}
	if loginResp.Token == "" {
		return fmt.Errorf("login succeeded but no token was returned")
	}

	c.token = loginResp.Token
	return nil
}

// Logout invalidates the current session token. Best effort — errors are
// returned but the token is cleared regardless.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.doGet(ctx, "/api/user/logout", nil)
	c.token = ""
	return err
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

// doGet performs a GET request to the Technitium API and returns the parsed response.
// Most Technitium API endpoints use GET with query parameters, including mutations.
func (c *Client) doGet(ctx context.Context, path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("token", c.token)

	reqURL := fmt.Sprintf("%s%s?%s", c.baseURL, path, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request to %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	return c.parseResponse(resp)
}

// doPost performs a POST request with form-encoded body (used by /api/settings/set).
func (c *Client) doPost(ctx context.Context, path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("token", c.token)

	reqURL := fmt.Sprintf("%s%s", c.baseURL, path)
	body := strings.NewReader(params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request to %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
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
