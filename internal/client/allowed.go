// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// AllowedZoneAdd adds a domain to the allowed zone list. Idempotent.
func (c *Client) AllowedZoneAdd(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.doGet(ctx, "/api/allowed/add", params)
	return err
}

// AllowedZoneDelete removes a domain from the allowed zone list. Idempotent.
func (c *Client) AllowedZoneDelete(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.doGet(ctx, "/api/allowed/delete", params)
	return err
}

// AllowedZoneExists checks whether a domain exists in the allowed zone list.
func (c *Client) AllowedZoneExists(ctx context.Context, domain string) (bool, error) {
	params := url.Values{}
	params.Set("domain", domain)
	resp, err := c.doGet(ctx, "/api/allowed/list", params)
	if err != nil {
		return false, err
	}

	var result filteredZoneListResponse
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return false, fmt.Errorf("decoding allowed zone list response: %w", err)
	}

	return len(result.Records) > 0, nil
}

// AllowedZoneList returns all domains in the allowed zone list.
func (c *Client) AllowedZoneList(ctx context.Context) ([]string, error) {
	return exportFilteredZones(ctx, c, "/api/allowed/export")
}

// AllowedZoneImport replaces the allowed zone list with the given domains.
func (c *Client) AllowedZoneImport(ctx context.Context, domains []string) error {
	params := url.Values{}
	params.Set("allowedZones", strings.Join(domains, ","))
	_, err := c.doGet(ctx, "/api/allowed/import", params)
	return err
}

// AllowedZoneFlush clears all entries from the allowed zone list.
func (c *Client) AllowedZoneFlush(ctx context.Context) error {
	_, err := c.doGet(ctx, "/api/allowed/flush", nil)
	return err
}
