// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	SkipTLSVerify bool   // default: false
	CACertFile    string
	CACertDir     string
	TLSServerName string
	TLSMinVersion string // "1.2" or "1.3", default: "1.3"
}

// Client is the Technitium DNS Server API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
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
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User explicitly opted in via skip_tls_verify
		}
	}

	return &Client{
		baseURL: cfg.BaseURL,
		token:   cfg.Token,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

// doGet performs a GET request to the Technitium API and returns the parsed response.
// Most Technitium API endpoints use GET with query parameters, including mutations.
func (c *Client) doGet(path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("token", c.token)

	reqURL := fmt.Sprintf("%s%s?%s", c.baseURL, path, params.Encode())
	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	return c.parseResponse(resp)
}

// doPost performs a POST request with form-encoded body (used by /api/settings/set).
func (c *Client) doPost(path string, params url.Values) (*APIResponse, error) {
	if params == nil {
		params = url.Values{}
	}
	params.Set("token", c.token)

	reqURL := fmt.Sprintf("%s%s", c.baseURL, path)
	resp, err := c.httpClient.PostForm(reqURL, params)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

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
func (c *Client) Ping() error {
	_, err := c.doGet("/api/user/session/get", nil)
	if err != nil {
		// Fallback: try settings endpoint (always exists, requires valid token)
		_, err = c.doGet("/api/settings/get", nil)
	}
	return err
}
