// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// filteredZoneListResponse is the response envelope for /api/blocked/list and
// /api/allowed/list. Records is non-empty when the queried domain exists.
type filteredZoneListResponse struct {
	Domain  string            `json:"domain"`
	Zones   []string          `json:"zones"`
	Records []json.RawMessage `json:"records"`
}

// exportFilteredZones fetches the plain-text export from the given path
// (e.g. /api/blocked/export or /api/allowed/export) and returns one domain
// per line. It bypasses doGet because the export endpoint returns plain text,
// not JSON.
//
// The API token is sent as an "Authorization: Bearer" header by default; in
// LegacyTokenAuth mode the request is a POST with the token as a form field.
func exportFilteredZones(ctx context.Context, c *Client, path string) ([]string, error) {
	reqURL := c.baseURL + path
	var req *http.Request
	var err error
	if c.legacyTokenAuth {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(url.Values{"token": {c.token}}.Encode()))
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	}
	if err != nil {
		return nil, redactRequestErr(path, err)
	}
	if c.legacyTokenAuth {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, redactTransportErr(path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from %s: %s", resp.StatusCode, path, c.errorBody(body))
	}

	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return []string{}, nil
	}
	switch text[0] {
	case '{':
		var env APIResponse
		if json.Unmarshal([]byte(text), &env) == nil && env.Status != "" && env.Status != "ok" {
			return nil, &APIError{Status: env.Status, ErrorMessage: c.redactSecrets(env.ErrorMessage)}
		}
		return nil, fmt.Errorf("unexpected JSON response from %s: %s", path, c.errorBody(body))
	case '[', '"':
		return nil, fmt.Errorf("unexpected JSON response from %s: %s", path, c.errorBody(body))
	case '<':
		return nil, fmt.Errorf("unexpected HTML response from %s: %s", path, c.errorBody(body))
	}

	lines := strings.Split(text, "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, nil
}

// BlockedZoneAdd adds a domain to the blocked zone list. Idempotent.
func (c *Client) BlockedZoneAdd(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.doPost(ctx, "/api/blocked/add", params)
	if err != nil {
		return fmt.Errorf("adding blocked zone %q: %w", domain, err)
	}
	return nil
}

// BlockedZoneDelete removes a domain from the blocked zone list. Idempotent.
func (c *Client) BlockedZoneDelete(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.doPost(ctx, "/api/blocked/delete", params)
	if err != nil {
		return fmt.Errorf("deleting blocked zone %q: %w", domain, err)
	}
	return nil
}

// BlockedZoneExists returns true if the domain exists in the blocked zone list.
func (c *Client) BlockedZoneExists(ctx context.Context, domain string) (bool, error) {
	params := url.Values{}
	params.Set("domain", domain)
	apiResp, err := c.doGet(ctx, "/api/blocked/list", params)
	if err != nil {
		return false, fmt.Errorf("checking blocked zone %q: %w", domain, err)
	}

	var listResp filteredZoneListResponse
	if err := json.Unmarshal(apiResp.Response, &listResp); err != nil {
		return false, fmt.Errorf("decoding blocked zone list response: %w", err)
	}

	return len(listResp.Records) > 0, nil
}

// BlockedZoneList returns all domains in the blocked zone list.
func (c *Client) BlockedZoneList(ctx context.Context) ([]string, error) {
	domains, err := exportFilteredZones(ctx, c, "/api/blocked/export")
	if err != nil {
		return nil, fmt.Errorf("listing blocked zones: %w", err)
	}
	return domains, nil
}

// BlockedZoneImport adds multiple domains to the blocked zone list in one call.
func (c *Client) BlockedZoneImport(ctx context.Context, domains []string) error {
	params := url.Values{}
	params.Set("blockedZones", strings.Join(domains, ","))
	_, err := c.doPost(ctx, "/api/blocked/import", params)
	if err != nil {
		return fmt.Errorf("importing blocked zones: %w", err)
	}
	return nil
}

// BlockedZoneFlush removes all domains from the blocked zone list.
func (c *Client) BlockedZoneFlush(ctx context.Context) error {
	_, err := c.doPost(ctx, "/api/blocked/flush", nil)
	if err != nil {
		return fmt.Errorf("flushing blocked zones: %w", err)
	}
	return nil
}
