// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Blocking type constants — valid values for the blockingType server setting.
const (
	BlockingTypeNxDomain      = "NxDomain"
	BlockingTypeAnyAddress    = "AnyAddress"
	BlockingTypeTxtRecord     = "TxtRecord"
	BlockingTypeCustomAddress = "CustomAddress"
)

// ValidBlockingTypes is the complete list of valid blocking type values.
var ValidBlockingTypes = []string{
	BlockingTypeNxDomain,
	BlockingTypeAnyAddress,
	BlockingTypeTxtRecord,
	BlockingTypeCustomAddress,
}

// ServerSettings represents the Technitium server settings from the API.
type ServerSettings struct {
	Version                    string   `json:"version"`
	Uptimestamp                string   `json:"uptimestamp"`
	DnsServerDomain            string   `json:"dnsServerDomain"`
	DnssecValidation           bool     `json:"dnssecValidation"`
	Recursion                  string   `json:"recursion"`
	RecursionNetworkACL        []string `json:"recursionNetworkACL"`
	QnameMinimization          bool     `json:"qnameMinimization"`
	RandomizeName              bool     `json:"randomizeName"`
	LogQueries                 bool     `json:"logQueries"`
	LoggingType                string   `json:"loggingType"`
	MaxLogFileDays             int      `json:"maxLogFileDays"`
	EnableBlocking              bool     `json:"enableBlocking"`
	AllowTxtBlockingReport      bool     `json:"allowTxtBlockingReport"`
	BlockingBypassList          []string `json:"blockingBypassList"`
	BlockingType                string   `json:"blockingType"`
	BlockingAnswerTTL           int      `json:"blockingAnswerTtl"`
	CustomBlockingAddresses     []string `json:"customBlockingAddresses"`
	BlockListUrls               []string `json:"blockListUrls"`
	BlockListUpdateIntervalHours int     `json:"blockListUpdateIntervalHours"`
	ServeStale                  bool     `json:"serveStale"`
	Forwarders                 []string `json:"forwarders"`
	ForwarderProtocol          string   `json:"forwarderProtocol"`
	EnableDnsOverTls           bool     `json:"enableDnsOverTls"`
	EnableDnsOverHttps         bool     `json:"enableDnsOverHttps"`
	ZoneTransferAllowedNetworks []string `json:"zoneTransferAllowedNetworks"`
	NotifyAllowedNetworks      []string `json:"notifyAllowedNetworks"`
	UdpPayloadSize             int      `json:"udpPayloadSize"`
	CacheMinimumRecordTtl      int      `json:"cacheMinimumRecordTtl"`
	CacheMaximumRecordTtl      int      `json:"cacheMaximumRecordTtl"`
	TsigKeys                   []TSIGKey `json:"tsigKeys"`
}

// SettingsGet returns the current server settings.
func (c *Client) SettingsGet(ctx context.Context) (*ServerSettings, error) {
	resp, err := c.doGet(ctx, "/api/settings/get", nil)
	if err != nil {
		return nil, fmt.Errorf("getting server settings: %w", err)
	}

	var settings ServerSettings
	if err := json.Unmarshal(resp.Response, &settings); err != nil {
		return nil, fmt.Errorf("parsing server settings: %w", err)
	}

	return &settings, nil
}

// SettingsSet updates server settings via POST.
func (c *Client) SettingsSet(ctx context.Context, params map[string]string) error {
	qp := url.Values{}
	for k, v := range params {
		qp.Set(k, v)
	}

	_, err := c.doPost(ctx, "/api/settings/set", qp)
	if err != nil {
		return fmt.Errorf("updating server settings: %w", err)
	}
	return nil
}
