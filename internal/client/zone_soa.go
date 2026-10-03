// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// SOARData is the rData of a zone's SOA record. UseSerialDateScheme is nil
// when the server does not report the field.
type SOARData struct {
	PrimaryNameServer   string `json:"primaryNameServer"`
	ResponsiblePerson   string `json:"responsiblePerson"`
	Serial              uint32 `json:"serial"`
	Refresh             uint32 `json:"refresh"`
	Retry               uint32 `json:"retry"`
	Expire              uint32 `json:"expire"`
	Minimum             uint32 `json:"minimum"`
	UseSerialDateScheme *bool  `json:"useSerialDateScheme"`
}

// SOARecord is a zone's apex SOA record.
type SOARecord struct {
	TTL      int
	Comments string
	RData    SOARData
}

// ZoneSOAGet returns the SOA record at the apex of zone.
func (c *Client) ZoneSOAGet(ctx context.Context, zone string) (*SOARecord, error) {
	records, err := c.RecordGet(ctx, zone, zone)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		if rec.Type != "SOA" {
			continue
		}
		raw, err := json.Marshal(rec.RData)
		if err != nil {
			return nil, fmt.Errorf("encoding SOA record for zone %q: %w", zone, err)
		}
		soa := &SOARecord{TTL: rec.TTL, Comments: rec.Comments}
		if err := json.Unmarshal(raw, &soa.RData); err != nil {
			return nil, fmt.Errorf("parsing SOA record for zone %q: %w", zone, err)
		}
		return soa, nil
	}
	return nil, fmt.Errorf("zone %q has no SOA record", zone)
}

// ZoneSOASetSerialDateScheme sets useSerialDateScheme on the zone's SOA
// record. records/update clears omitted fields and bumps the serial on every
// call: send every field as read, and skip the write when nothing changes.
func (c *Client) ZoneSOASetSerialDateScheme(ctx context.Context, zone string, want bool) error {
	soa, err := c.ZoneSOAGet(ctx, zone)
	if err != nil {
		return err
	}
	if cur := soa.RData.UseSerialDateScheme; cur == nil || *cur == want {
		return nil
	}
	u32 := func(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
	return c.RecordUpdate(ctx, zone, zone, "SOA", soa.TTL, map[string]string{
		"primaryNameServer":   soa.RData.PrimaryNameServer,
		"responsiblePerson":   soa.RData.ResponsiblePerson,
		"serial":              u32(soa.RData.Serial),
		"refresh":             u32(soa.RData.Refresh),
		"retry":               u32(soa.RData.Retry),
		"expire":              u32(soa.RData.Expire),
		"minimum":             u32(soa.RData.Minimum),
		"useSerialDateScheme": strconv.FormatBool(want),
		"comments":            soa.Comments,
	})
}
