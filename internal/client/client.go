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
	// LegacyTokenAuth sends every request as a POST with the API token in a
	// "token" form field instead of an "Authorization: Bearer" header, for
	// Technitium DNS Server versions before 15.0. Default: false.
	LegacyTokenAuth bool
}

// Client is the Technitium DNS Server API client.
type Client struct {
	baseURL         string
	token           string
	username        string
	password        string
	legacyTokenAuth bool
	httpClient      *http.Client
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
	isHTTPS := IsHTTPSURL(cfg.BaseURL)

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
		username:        cfg.Username,
		password:        cfg.Password,
		legacyTokenAuth: cfg.LegacyTokenAuth,
		httpClient: &http.Client{
			Timeout:       time.Duration(cfg.TimeoutSeconds) * time.Second,
			Transport:     transport,
			CheckRedirect: checkRedirect,
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
		return redactRequestErr("/api/user/login", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return redactTransportErr("/api/user/login", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading login response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d on login: %s", resp.StatusCode, c.errorBody(respBody))
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
		return &APIError{Status: loginResp.Status, ErrorMessage: c.redactSecrets(loginResp.ErrorMessage)}
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
	_, err := c.doPost(ctx, "/api/user/logout", nil)
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

// IsHTTPSURL reports whether rawURL uses the https scheme, in any case.
func IsHTTPSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// RedactURL returns rawURL without userinfo, query string, or fragment, or a
// fixed placeholder if rawURL does not parse.
func RedactURL(rawURL string) string {
	return redactURL(rawURL)
}

func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[redacted URL]"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// redactTransportErr converts an error returned by (*http.Client).Do into
// an error safe to surface to the user (e.g. via a Terraform diagnostic).
// http.Client.Do returns a *url.Error whose Error() method embeds the full
// request URL verbatim, including the query string — so wrapping it
// directly with %w would still render that URL whenever the resulting
// error's Error() is later called. This rebuilds the message from a
// query-stripped URL and wraps only the innermost cause, so errors.As-based
// classification (e.g. ClassifyTLSError) keeps working against the
// unwrapped chain.
func redactTransportErr(path string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if strings.HasPrefix(urlErr.Err.Error(), "failed to parse Location header") {
			return fmt.Errorf("%s %s failed: server sent an unparseable redirect Location header", urlErr.Op, redactURL(urlErr.URL))
		}
		return fmt.Errorf("%s %s failed: %w", urlErr.Op, redactURL(urlErr.URL), urlErr.Err)
	}
	return fmt.Errorf("request to %s failed: %w", path, err)
}

// redactRequestErr is the request-creation counterpart of redactTransportErr.
// http.NewRequestWithContext fails with a *url.Error when the URL does not
// parse -- a server_url with a stray space, for example -- and that error's
// message embeds the raw URL, query string included. redactURL cannot parse
// such a URL either, so the URL is replaced by its placeholder.
func redactRequestErr(path string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("creating request to %s: %s %s: %w", path, urlErr.Op, redactURL(urlErr.URL), urlErr.Err)
	}
	return fmt.Errorf("creating request to %s: %w", path, err)
}

// maxErrorBodyBytes caps how much of a non-200 response body is quoted in an
// error message.
const maxErrorBodyBytes = 512

// errorBody renders a non-200 response body for an error message. Reverse
// proxies and WAFs routinely echo the request URI or form body in their error
// pages, which in LegacyTokenAuth mode carries the API token (and, on login,
// the password). Every credential the client holds is replaced -- raw and in
// its URL-encoded forms -- before the body is truncated, so truncation can
// never leave a partial credential behind.
func (c *Client) errorBody(body []byte) string {
	return c.errorBodyWith(body, nil)
}

func (c *Client) errorBodyWith(body []byte, extra []string) string {
	s := c.redactSecrets(string(body), extra...)
	if len(s) > maxErrorBodyBytes {
		s = strings.ToValidUTF8(s[:maxErrorBodyBytes], "") + " [truncated]"
	}
	return s
}

func (c *Client) redactSecrets(s string, extra ...string) string {
	for _, secret := range append([]string{c.token, c.password}, extra...) {
		if secret == "" {
			continue
		}
		for _, form := range []string{secret, url.QueryEscape(secret), url.PathEscape(secret)} {
			s = strings.ReplaceAll(s, form, "[REDACTED]")
		}
	}
	return s
}

// doGet performs a GET request with the parameters in the query string.
// Writes use doPost. In LegacyTokenAuth mode it delegates to doPost so the
// token never appears in a URL.
func (c *Client) doGet(ctx context.Context, path string, params url.Values) (*APIResponse, error) {
	if c.legacyTokenAuth {
		return c.doPost(ctx, path, params)
	}

	reqURL := c.baseURL + path
	if encoded := params.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, redactRequestErr(path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, redactTransportErr(path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	return c.parseResponse(resp)
}

// doPost performs a POST request with a form-encoded body.
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
		return nil, redactRequestErr(path, err)
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

	return c.parseResponseWith(resp, requestSecrets(params))
}

// parseResponse reads the response body and checks for API-level errors.
func (c *Client) parseResponse(resp *http.Response) (*APIResponse, error) {
	return c.parseResponseWith(resp, nil)
}

func (c *Client) parseResponseWith(resp *http.Response, extra []string) (*APIResponse, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, c.errorBodyWith(body, extra))
	}

	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("decoding response JSON: %w", err)
	}

	if apiResp.Status != "ok" {
		return nil, &APIError{
			Status:       apiResp.Status,
			ErrorMessage: c.redactSecrets(apiResp.ErrorMessage, extra...),
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

// Redirect policy: #124.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	orig := via[0].URL
	if req.URL.Scheme != orig.Scheme || !strings.EqualFold(req.URL.Hostname(), orig.Hostname()) || effectivePort(req.URL) != effectivePort(orig) {
		return fmt.Errorf("refusing redirect from %s to %s: set server_url to the final address",
			redactURL(orig.String()), redactURL(req.URL.String()))
	}
	return nil
}

var secretParams = []string{"pass", "newPass", "proxyPassword", "primaryNodePassword", "primaryNodeTotp", "ssoClientSecret", "webServiceTlsCertificatePassword"}

func requestSecrets(params url.Values) []string {
	var out []string
	for _, k := range secretParams {
		out = append(out, params[k]...)
	}
	for _, v := range params["tsigKeys"] {
		parts := strings.Split(v, "|")
		for i := 1; i < len(parts); i += 3 {
			out = append(out, parts[i])
		}
	}
	return out
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
