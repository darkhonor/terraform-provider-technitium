// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Record represents a DNS record from the Technitium API.
type Record struct {
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	TTL          int                    `json:"ttl"`
	Disabled     bool                   `json:"disabled"`
	RData        map[string]interface{} `json:"rData"`
	LastModified string                 `json:"lastModified"`
	// Comments is the free-text note stored with the record. The API omits it
	// (or sends null) when no comment is set; both decode to "".
	Comments string `json:"comments"`
}

// RecordAddResponse is the response from adding a record.
type RecordAddResponse struct {
	Zone        json.RawMessage `json:"zone"`
	AddedRecord Record          `json:"addedRecord"`
}

// RecordGetResponse is the response from getting records.
type RecordGetResponse struct {
	Zone    json.RawMessage `json:"zone"`
	Records []Record        `json:"records"`
}

// RecordAdd adds a DNS record to a zone.
// The params map should contain type-specific parameters:
//   - A/AAAA: "ipAddress"
//   - CNAME: "cname"
//   - MX: "exchange", "preference"
//   - TXT: "text"
//   - SRV: "priority", "weight", "port", "target"
//   - PTR: "ptrName"
//   - NS: "nameServer"
//   - CAA: "flags", "tag", "value"
//   - FWD: "protocol", "forwarder", "forwarderPriority", "dnssecValidation"
func (c *Client) RecordAdd(ctx context.Context, domain, zone, recordType string, ttl int, overwrite bool, params map[string]string) (*Record, error) {
	qp := url.Values{
		"domain": {domain},
		"zone":   {zone},
		"type":   {recordType},
	}
	if ttl > 0 {
		qp.Set("ttl", fmt.Sprintf("%d", ttl))
	}
	if overwrite {
		qp.Set("overwrite", "true")
	}
	for k, v := range params {
		qp.Set(k, v)
	}

	resp, err := c.doGet(ctx, "/api/zones/records/add", qp)
	if err != nil {
		return nil, fmt.Errorf("adding %s record for %q in zone %q: %w", recordType, domain, zone, err)
	}

	var result RecordAddResponse
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return nil, fmt.Errorf("parsing add record response: %w", err)
	}

	return &result.AddedRecord, nil
}

// RecordGet retrieves records for a domain in a zone, optionally filtered by type.
func (c *Client) RecordGet(ctx context.Context, domain, zone string) ([]Record, error) {
	qp := url.Values{
		"domain": {domain},
		"zone":   {zone},
	}

	resp, err := c.doGet(ctx, "/api/zones/records/get", qp)
	if err != nil {
		return nil, fmt.Errorf("getting records for %q in zone %q: %w", domain, zone, err)
	}

	var result RecordGetResponse
	if err := json.Unmarshal(resp.Response, &result); err != nil {
		return nil, fmt.Errorf("parsing get records response: %w", err)
	}

	return result.Records, nil
}

// RecordUpdate updates an existing DNS record.
// The params map should contain both current and new values as needed by the API.
// For A/AAAA: "ipAddress" (current), "newIpAddress" (new)
// For CNAME: "cname" (new value)
// For MX: "exchange" (current), "newExchange" (new), "preference", "newPreference"
// etc.
//
// 🚩 The current/new pairing does NOT extend to every field. FWD records have
// "forwarder"/"newForwarder", "protocol"/"newProtocol" and
// "forwarderPriority"/"newForwarderPriority", but "dnssecValidation" has no
// "new" counterpart — it is the new value, and the old one cannot be supplied
// as an identifier. Two FWD records differing only by that flag therefore
// cannot be updated independently: the update rewrites one onto the other and
// they collapse into a single record, reported as status "ok". Omitting
// "dnssecValidation" entirely is also not "leave unchanged" — it resets the
// record to false. Both verified on Technitium 15.2 and 15.4 and reported
// upstream as TechnitiumSoftware/DnsServer#2069.
func (c *Client) RecordUpdate(ctx context.Context, domain, zone, recordType string, ttl int, params map[string]string) error {
	qp := url.Values{
		"domain": {domain},
		"zone":   {zone},
		"type":   {recordType},
	}
	if ttl > 0 {
		qp.Set("ttl", fmt.Sprintf("%d", ttl))
	}
	for k, v := range params {
		qp.Set(k, v)
	}

	_, err := c.doGet(ctx, "/api/zones/records/update", qp)
	if err != nil {
		return fmt.Errorf("updating %s record for %q in zone %q: %w", recordType, domain, zone, err)
	}
	return nil
}

// RecordDelete deletes a DNS record.
// The params map should contain the type-specific identifier to match the record:
//   - A/AAAA: "ipAddress"
//   - CNAME: "cname"
//   - MX: "exchange", "preference"
//   - TXT: "text"
//   - SRV: "priority", "weight", "port", "target"
//   - PTR: "ptrName"
//   - NS: "nameServer"
//   - CAA: "flags", "tag", "value"
//   - FWD: "protocol", "forwarder", "forwarderPriority", "dnssecValidation"
//
// 🚩 "dnssecValidation" appears above because the provider sends it, NOT because
// the server matches on it. Technitium 15.2 and 15.4 ignore it when selecting
// which record to delete: given two FWD records identical apart from that flag,
// the first-created one is removed whatever value is supplied, and the call
// still returns status "ok". Do not assume this call can target one of a
// colliding pair. Reported upstream as TechnitiumSoftware/DnsServer#2069.
func (c *Client) RecordDelete(ctx context.Context, domain, zone, recordType string, params map[string]string) error {
	qp := url.Values{
		"domain": {domain},
		"zone":   {zone},
		"type":   {recordType},
	}
	for k, v := range params {
		qp.Set(k, v)
	}

	_, err := c.doGet(ctx, "/api/zones/records/delete", qp)
	if err != nil {
		return fmt.Errorf("deleting %s record for %q in zone %q: %w", recordType, domain, zone, err)
	}
	return nil
}

// RecordValueParam returns the API parameter name for a record type's primary value.
// Used to map the generic "value" field to the type-specific API parameter.
func RecordValueParam(recordType string) string {
	switch recordType {
	case "A", "AAAA":
		return "ipAddress"
	case "CNAME":
		return "cname"
	case "MX":
		return "exchange"
	case "TXT":
		return "text"
	case "SRV":
		return "target"
	case "PTR":
		return "ptrName"
	case "NS":
		return "nameServer"
	case "CAA":
		return "value"
	case "FWD":
		return "forwarder"
	default:
		return "value"
	}
}

// RecordValueFromRData extracts the primary value from an rData map.
func RecordValueFromRData(recordType string, rData map[string]interface{}) string {
	key := RecordValueParam(recordType)
	if v, ok := rData[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
