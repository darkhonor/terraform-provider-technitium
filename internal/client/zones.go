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

// Zone represents a Technitium DNS zone from the API.
type Zone struct {
	Name                   string   `json:"name"`
	Type                   string   `json:"type"`
	Internal               bool     `json:"internal"`
	Disabled               bool     `json:"disabled"`
	DNSSECStatus           string   `json:"dnssecStatus"`
	SOASerial              int      `json:"soaSerial"`
	NotifyFailed           bool     `json:"notifyFailed"`
	NotifyFailedFor        []string `json:"notifyFailedFor"`
	Catalog                *string  `json:"catalog"`
	QueryAccess            string   `json:"queryAccess"`
	QueryAccessNetworkACL  []string `json:"queryAccessNetworkACL"`
	ZoneTransfer           string   `json:"zoneTransfer"`
	ZoneTransferNetworkACL []string `json:"zoneTransferNetworkACL"`
	ZoneTransferTsigKeys           []string `json:"zoneTransferTsigKeyNames"`
	PrimaryZoneTransferTsigKeyName string   `json:"primaryZoneTransferTsigKeyName"`
	Notify                         string   `json:"notify"`
	NotifyNameServers      []string `json:"notifyNameServers"`
	Update                 string   `json:"update"`
	UpdateNetworkACL       []string `json:"updateNetworkACL"`
}

// ZoneListItem is a zone entry from /api/zones/list.
type ZoneListItem struct {
	Name                 string  `json:"name"`
	Type                 string  `json:"type"`
	Disabled             bool    `json:"disabled"`
	SOASerial            int     `json:"soaSerial"`
	Internal             bool    `json:"internal"`
	Catalog              *string `json:"catalog"`
	DNSSECStatus         string  `json:"dnssecStatus"`
	HasDNSSECPrivateKeys bool    `json:"hasDnssecPrivateKeys"`
	LastModified         string  `json:"lastModified"`
}

// DNSSECProperties holds DNSSEC signing info for a zone.
type DNSSECProperties struct {
	Name             string           `json:"name"`
	Type             string           `json:"type"`
	DNSSECStatus     string           `json:"dnssecStatus"`
	NSEC3Iterations  int              `json:"nsec3Iterations"`
	NSEC3SaltLength  int              `json:"nsec3SaltLength"`
	DNSKeyTTL        int              `json:"dnsKeyTtl"`
	DNSSECPrivateKeys []DNSSECKey     `json:"dnssecPrivateKeys"`
}

// DNSSECKey represents a DNSSEC private key.
type DNSSECKey struct {
	KeyTag          int    `json:"keyTag"`
	KeyType         string `json:"keyType"`
	Algorithm       string `json:"algorithm"`
	AlgorithmNumber int    `json:"algorithmNumber"`
	State           string `json:"state"`
	IsRetiring      bool   `json:"isRetiring"`
	RolloverDays    int    `json:"rolloverDays"`
}

// DSRecord represents a DS record from /api/zones/dnssec/viewDS.
type DSRecord struct {
	KeyTag    int    `json:"keyTag"`
	Algorithm string `json:"algorithm"`
	Digests   []struct {
		DigestType       string `json:"digestType"`
		Digest           string `json:"digest"`
	} `json:"digests"`
}

// DSInfo holds DS record information for a zone.
type DSInfo struct {
	Name         string     `json:"name"`
	DNSSECStatus string     `json:"dnssecStatus"`
	DSRecords    []DSRecord `json:"dsRecords"`
}

// ZoneCreate creates a new authoritative zone.
func (c *Client) ZoneCreate(ctx context.Context, name, zoneType string, useSoaSerialDateScheme bool) (string, error) {
	params := url.Values{
		"zone": {name},
		"type": {zoneType},
	}
	if useSoaSerialDateScheme {
		params.Set("useSoaSerialDateScheme", "true")
	}

	resp, err := c.doGet(ctx, "/api/zones/create", params)
	if err != nil {
		return "", fmt.Errorf("creating zone %q: %w", name, err)
	}

	var result struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return "", fmt.Errorf("parsing create zone response: %w", err)
	}

	return result.Domain, nil
}

// ZoneDelete deletes an authoritative zone.
func (c *Client) ZoneDelete(ctx context.Context, name string) error {
	params := url.Values{
		"zone": {name},
	}
	_, err := c.doGet(ctx, "/api/zones/delete", params)
	if err != nil {
		return fmt.Errorf("deleting zone %q: %w", name, err)
	}
	return nil
}

// ZoneList returns all authoritative zones.
func (c *Client) ZoneList(ctx context.Context) ([]ZoneListItem, error) {
	resp, err := c.doGet(ctx, "/api/zones/list", nil)
	if err != nil {
		return nil, fmt.Errorf("listing zones: %w", err)
	}

	var result struct {
		Zones []ZoneListItem `json:"zones"`
	}
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return nil, fmt.Errorf("parsing zone list response: %w", err)
	}

	return result.Zones, nil
}

// ZoneOptionsGet returns the zone-specific options.
func (c *Client) ZoneOptionsGet(ctx context.Context, name string) (*Zone, error) {
	params := url.Values{
		"zone": {name},
	}
	resp, err := c.doGet(ctx, "/api/zones/options/get", params)
	if err != nil {
		return nil, fmt.Errorf("getting zone options for %q: %w", name, err)
	}

	var zone Zone
	if err := json.Unmarshal(resp.Response, &zone); err != nil {
		return nil, fmt.Errorf("parsing zone options response: %w", err)
	}

	return &zone, nil
}

// ZoneOptionsSet updates zone-specific options.
func (c *Client) ZoneOptionsSet(ctx context.Context, name string, opts map[string]string) error {
	params := url.Values{
		"zone": {name},
	}
	for k, v := range opts {
		params.Set(k, v)
	}

	_, err := c.doGet(ctx, "/api/zones/options/set", params)
	if err != nil {
		return fmt.Errorf("setting zone options for %q: %w", name, err)
	}
	return nil
}

// ZoneDNSSECSign signs a zone with DNSSEC.
// algorithm: RSA, ECDSA, EDDSA
// curve: P256, P384 (ECDSA) or ED25519, ED448 (EDDSA)
// nxProof: NSEC or NSEC3
func (c *Client) ZoneDNSSECSign(ctx context.Context, name, algorithm, curve, nxProof string) error {
	params := url.Values{
		"zone":      {name},
		"algorithm": {algorithm},
		"nxProof":   {nxProof},
	}
	if curve != "" {
		params.Set("curve", curve)
	}
	// Sensible defaults for DNSSEC key management
	params.Set("dnsKeyTtl", "86400")
	params.Set("zskRolloverDays", "30")
	if nxProof == "NSEC3" {
		params.Set("iterations", "0")
		params.Set("saltLength", "0")
	}

	_, err := c.doGet(ctx, "/api/zones/dnssec/sign", params)
	if err != nil {
		return fmt.Errorf("signing zone %q with DNSSEC: %w", name, err)
	}
	return nil
}

// ZoneDNSSECUnsign removes DNSSEC from a zone.
func (c *Client) ZoneDNSSECUnsign(ctx context.Context, name string) error {
	params := url.Values{
		"zone": {name},
	}
	_, err := c.doGet(ctx, "/api/zones/dnssec/unsign", params)
	if err != nil {
		return fmt.Errorf("unsigning zone %q: %w", name, err)
	}
	return nil
}

// ZoneDNSSECPropertiesGet returns DNSSEC properties for a zone.
func (c *Client) ZoneDNSSECPropertiesGet(ctx context.Context, name string) (*DNSSECProperties, error) {
	params := url.Values{
		"zone": {name},
	}
	resp, err := c.doGet(ctx, "/api/zones/dnssec/properties/get", params)
	if err != nil {
		return nil, fmt.Errorf("getting DNSSEC properties for %q: %w", name, err)
	}

	var props DNSSECProperties
	if err := json.Unmarshal(resp.Response, &props); err != nil {
		return nil, fmt.Errorf("parsing DNSSEC properties response: %w", err)
	}

	return &props, nil
}

// ZoneDNSSECViewDS returns DS records for a signed zone.
func (c *Client) ZoneDNSSECViewDS(ctx context.Context, name string) (*DSInfo, error) {
	params := url.Values{
		"zone": {name},
	}
	resp, err := c.doGet(ctx, "/api/zones/dnssec/viewDS", params)
	if err != nil {
		return nil, fmt.Errorf("getting DS records for %q: %w", name, err)
	}

	var info DSInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("parsing DS records response: %w", err)
	}

	return &info, nil
}

// ZoneExists checks if a zone exists by name.
func (c *Client) ZoneExists(ctx context.Context, name string) (bool, error) {
	zones, err := c.ZoneList(ctx)
	if err != nil {
		return false, err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return true, nil
		}
	}
	return false, nil
}
