// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// buildRecordID tests
// ---------------------------------------------------------------------------

func TestBuildRecordID_SimpleTypes(t *testing.T) {
	tests := []struct {
		name     string
		model    RecordResourceModel
		expected string
	}{
		{
			name: "A record",
			model: RecordResourceModel{
				Zone:  types.StringValue("example.com"),
				Name:  types.StringValue("www.example.com"),
				Type:  types.StringValue("A"),
				Value: types.StringValue("192.168.1.1"),
			},
			expected: "example.com::www.example.com::A::192.168.1.1",
		},
		{
			name: "AAAA record",
			model: RecordResourceModel{
				Zone:  types.StringValue("example.com"),
				Name:  types.StringValue("www.example.com"),
				Type:  types.StringValue("AAAA"),
				Value: types.StringValue("2001:db8::1"),
			},
			expected: "example.com::www.example.com::AAAA::2001:db8::1",
		},
		{
			name: "CNAME record",
			model: RecordResourceModel{
				Zone:  types.StringValue("example.com"),
				Name:  types.StringValue("alias.example.com"),
				Type:  types.StringValue("CNAME"),
				Value: types.StringValue("www.example.com"),
			},
			expected: "example.com::alias.example.com::CNAME::www.example.com",
		},
		{
			name: "TXT record",
			model: RecordResourceModel{
				Zone:  types.StringValue("example.com"),
				Name:  types.StringValue("example.com"),
				Type:  types.StringValue("TXT"),
				Value: types.StringValue("v=spf1 include:_spf.google.com ~all"),
			},
			expected: "example.com::example.com::TXT::v=spf1 include:_spf.google.com ~all",
		},
		{
			name: "PTR record",
			model: RecordResourceModel{
				Zone:  types.StringValue("1.168.192.in-addr.arpa"),
				Name:  types.StringValue("1.1.168.192.in-addr.arpa"),
				Type:  types.StringValue("PTR"),
				Value: types.StringValue("host.example.com"),
			},
			expected: "1.168.192.in-addr.arpa::1.1.168.192.in-addr.arpa::PTR::host.example.com",
		},
		{
			name: "NS record",
			model: RecordResourceModel{
				Zone:  types.StringValue("example.com"),
				Name:  types.StringValue("example.com"),
				Type:  types.StringValue("NS"),
				Value: types.StringValue("ns1.example.com"),
			},
			expected: "example.com::example.com::NS::ns1.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildRecordID(&tc.model)
			if got != tc.expected {
				t.Errorf("buildRecordID() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestBuildRecordID_MX(t *testing.T) {
	model := RecordResourceModel{
		Zone:     types.StringValue("example.com"),
		Name:     types.StringValue("example.com"),
		Type:     types.StringValue("MX"),
		Value:    types.StringValue("mail.example.com"),
		Priority: types.Int64Value(10),
	}
	expected := "example.com::example.com::MX::mail.example.com:10"
	got := buildRecordID(&model)
	if got != expected {
		t.Errorf("buildRecordID() = %q, want %q", got, expected)
	}
}

func TestBuildRecordID_SRV(t *testing.T) {
	model := RecordResourceModel{
		Zone:     types.StringValue("example.com"),
		Name:     types.StringValue("_sip._tcp.example.com"),
		Type:     types.StringValue("SRV"),
		Value:    types.StringValue("sip.example.com"),
		Priority: types.Int64Value(10),
		Weight:   types.Int64Value(60),
		Port:     types.Int64Value(5060),
	}
	expected := "example.com::_sip._tcp.example.com::SRV::sip.example.com:10:60:5060"
	got := buildRecordID(&model)
	if got != expected {
		t.Errorf("buildRecordID() = %q, want %q", got, expected)
	}
}

func TestBuildRecordID_CAA(t *testing.T) {
	model := RecordResourceModel{
		Zone:     types.StringValue("example.com"),
		Name:     types.StringValue("example.com"),
		Type:     types.StringValue("CAA"),
		Value:    types.StringValue("letsencrypt.org"),
		CAAFlags: types.Int64Value(0),
		CAATag:   types.StringValue("issue"),
	}
	expected := "example.com::example.com::CAA::letsencrypt.org:0:issue"
	got := buildRecordID(&model)
	if got != expected {
		t.Errorf("buildRecordID() = %q, want %q", got, expected)
	}
}

// ---------------------------------------------------------------------------
// parseRecordID tests
// ---------------------------------------------------------------------------

func TestParseRecordID_Valid(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		wantZone     string
		wantName     string
		wantType     string
		wantValueSeg string
	}{
		{
			name:         "A record",
			id:           "example.com::www.example.com::A::192.168.1.1",
			wantZone:     "example.com",
			wantName:     "www.example.com",
			wantType:     "A",
			wantValueSeg: "192.168.1.1",
		},
		{
			name:         "AAAA with colons in value",
			id:           "example.com::www.example.com::AAAA::2001:db8::1",
			wantZone:     "example.com",
			wantName:     "www.example.com",
			wantType:     "AAAA",
			wantValueSeg: "2001:db8::1",
		},
		{
			name:         "MX with compound value",
			id:           "example.com::example.com::MX::mail.example.com:10",
			wantZone:     "example.com",
			wantName:     "example.com",
			wantType:     "MX",
			wantValueSeg: "mail.example.com:10",
		},
		{
			name:         "SRV with compound value",
			id:           "example.com::_sip._tcp.example.com::SRV::sip.example.com:10:60:5060",
			wantZone:     "example.com",
			wantName:     "_sip._tcp.example.com",
			wantType:     "SRV",
			wantValueSeg: "sip.example.com:10:60:5060",
		},
		{
			name:         "CAA with compound value",
			id:           "example.com::example.com::CAA::letsencrypt.org:0:issue",
			wantZone:     "example.com",
			wantName:     "example.com",
			wantType:     "CAA",
			wantValueSeg: "letsencrypt.org:0:issue",
		},
		{
			name:         "TXT with special characters",
			id:           "example.com::example.com::TXT::v=spf1 include:_spf.google.com ~all",
			wantZone:     "example.com",
			wantName:     "example.com",
			wantType:     "TXT",
			wantValueSeg: "v=spf1 include:_spf.google.com ~all",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zone, name, recordType, valueSeg, err := parseRecordID(tc.id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if zone != tc.wantZone {
				t.Errorf("zone = %q, want %q", zone, tc.wantZone)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if recordType != tc.wantType {
				t.Errorf("type = %q, want %q", recordType, tc.wantType)
			}
			if valueSeg != tc.wantValueSeg {
				t.Errorf("valueSegment = %q, want %q", valueSeg, tc.wantValueSeg)
			}
		})
	}
}

func TestParseRecordID_Invalid(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"empty string", ""},
		{"single segment", "example.com"},
		{"two segments", "example.com::www.example.com"},
		{"three segments", "example.com::www.example.com::A"},
		{"empty value segment", "example.com::www.example.com::A::"},
		{"old format with slashes", "example.com/www.example.com/A"},
		{"empty zone", "::name::A::1.2.3.4"},
		{"empty name", "example.com::::A::1.2.3.4"},
		{"empty type", "example.com::www.example.com::::1.2.3.4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := parseRecordID(tc.id)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseImportValueSegment tests
// ---------------------------------------------------------------------------

func TestParseImportValueSegment_SimpleTypes(t *testing.T) {
	simpleTypes := []string{"A", "AAAA", "CNAME", "TXT", "PTR", "NS"}
	for _, rt := range simpleTypes {
		t.Run(rt, func(t *testing.T) {
			value, priority, weight, port, caaFlags, caaTag, err := parseImportValueSegment(rt, "some-value")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if value != "some-value" {
				t.Errorf("value = %q, want %q", value, "some-value")
			}
			if priority != 0 || weight != 0 || port != 0 || caaFlags != 0 || caaTag != "" {
				t.Error("expected zero values for non-applicable fields")
			}
		})
	}
}

func TestParseImportValueSegment_MX(t *testing.T) {
	value, priority, weight, port, caaFlags, caaTag, err := parseImportValueSegment("MX", "mail.example.com:10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "mail.example.com" {
		t.Errorf("value = %q, want %q", value, "mail.example.com")
	}
	if priority != 10 {
		t.Errorf("priority = %d, want 10", priority)
	}
	if weight != 0 || port != 0 || caaFlags != 0 || caaTag != "" {
		t.Error("expected zero values for non-MX fields")
	}
}

func TestParseImportValueSegment_MX_InvalidPriority(t *testing.T) {
	_, _, _, _, _, _, err := parseImportValueSegment("MX", "mail.example.com:abc")
	if err == nil {
		t.Error("expected error for non-numeric priority")
	}
}

func TestParseImportValueSegment_MX_NoColon(t *testing.T) {
	_, _, _, _, _, _, err := parseImportValueSegment("MX", "mail.example.com")
	if err == nil {
		t.Error("expected error for MX without priority")
	}
}

func TestParseImportValueSegment_SRV(t *testing.T) {
	value, priority, weight, port, caaFlags, caaTag, err := parseImportValueSegment("SRV", "sip.example.com:10:60:5060")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "sip.example.com" {
		t.Errorf("value = %q, want %q", value, "sip.example.com")
	}
	if priority != 10 {
		t.Errorf("priority = %d, want 10", priority)
	}
	if weight != 60 {
		t.Errorf("weight = %d, want 60", weight)
	}
	if port != 5060 {
		t.Errorf("port = %d, want 5060", port)
	}
	if caaFlags != 0 || caaTag != "" {
		t.Error("expected zero values for non-SRV fields")
	}
}

func TestParseImportValueSegment_SRV_TooFewFields(t *testing.T) {
	_, _, _, _, _, _, err := parseImportValueSegment("SRV", "sip.example.com:10:60")
	if err == nil {
		t.Error("expected error for SRV with too few colon-separated fields")
	}
}

func TestParseImportValueSegment_SRV_InvalidNumeric(t *testing.T) {
	_, _, _, _, _, _, err := parseImportValueSegment("SRV", "sip.example.com:abc:60:5060")
	if err == nil {
		t.Error("expected error for SRV with non-numeric priority")
	}
}

func TestParseImportValueSegment_CAA(t *testing.T) {
	value, priority, weight, port, caaFlags, caaTag, err := parseImportValueSegment("CAA", "letsencrypt.org:0:issue")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "letsencrypt.org" {
		t.Errorf("value = %q, want %q", value, "letsencrypt.org")
	}
	if caaFlags != 0 {
		t.Errorf("caaFlags = %d, want 0", caaFlags)
	}
	if caaTag != "issue" {
		t.Errorf("caaTag = %q, want %q", caaTag, "issue")
	}
	if priority != 0 || weight != 0 || port != 0 {
		t.Error("expected zero values for non-CAA fields")
	}
}

func TestParseImportValueSegment_CAA_CriticalFlag(t *testing.T) {
	value, _, _, _, caaFlags, caaTag, err := parseImportValueSegment("CAA", "ca.example.com:128:issuewild")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "ca.example.com" {
		t.Errorf("value = %q, want %q", value, "ca.example.com")
	}
	if caaFlags != 128 {
		t.Errorf("caaFlags = %d, want 128", caaFlags)
	}
	if caaTag != "issuewild" {
		t.Errorf("caaTag = %q, want %q", caaTag, "issuewild")
	}
}

func TestParseImportValueSegment_CAA_TooFewFields(t *testing.T) {
	_, _, _, _, _, _, err := parseImportValueSegment("CAA", "letsencrypt.org:0")
	if err == nil {
		t.Error("expected error for CAA with too few colon-separated fields")
	}
}

// ---------------------------------------------------------------------------
// recordMatchesState tests
// ---------------------------------------------------------------------------

func TestRecordMatchesState_ARecord(t *testing.T) {
	rec := client.Record{
		Type:  "A",
		RData: map[string]interface{}{"ipAddress": "192.168.1.1"},
	}
	state := &RecordResourceModel{
		Type:  types.StringValue("A"),
		Value: types.StringValue("192.168.1.1"),
	}
	if !recordMatchesState(rec, state) {
		t.Error("expected match for identical A record")
	}
}

func TestRecordMatchesState_ARecord_Mismatch(t *testing.T) {
	rec := client.Record{
		Type:  "A",
		RData: map[string]interface{}{"ipAddress": "192.168.1.2"},
	}
	state := &RecordResourceModel{
		Type:  types.StringValue("A"),
		Value: types.StringValue("192.168.1.1"),
	}
	if recordMatchesState(rec, state) {
		t.Error("expected no match for different A record values")
	}
}

func TestRecordMatchesState_TypeMismatch(t *testing.T) {
	rec := client.Record{
		Type:  "AAAA",
		RData: map[string]interface{}{"ipAddress": "192.168.1.1"},
	}
	state := &RecordResourceModel{
		Type:  types.StringValue("A"),
		Value: types.StringValue("192.168.1.1"),
	}
	if recordMatchesState(rec, state) {
		t.Error("expected no match for different record types")
	}
}

func TestRecordMatchesState_MX_Match(t *testing.T) {
	rec := client.Record{
		Type: "MX",
		RData: map[string]interface{}{
			"exchange":   "mail.example.com",
			"preference": float64(10),
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("MX"),
		Value:    types.StringValue("mail.example.com"),
		Priority: types.Int64Value(10),
	}
	if !recordMatchesState(rec, state) {
		t.Error("expected match for identical MX record")
	}
}

func TestRecordMatchesState_MX_DifferentPriority(t *testing.T) {
	rec := client.Record{
		Type: "MX",
		RData: map[string]interface{}{
			"exchange":   "mail.example.com",
			"preference": float64(20),
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("MX"),
		Value:    types.StringValue("mail.example.com"),
		Priority: types.Int64Value(10),
	}
	if recordMatchesState(rec, state) {
		t.Error("expected no match for MX with different preference")
	}
}

func TestRecordMatchesState_SRV_Match(t *testing.T) {
	rec := client.Record{
		Type: "SRV",
		RData: map[string]interface{}{
			"target":   "sip.example.com",
			"priority": float64(10),
			"weight":   float64(60),
			"port":     float64(5060),
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("SRV"),
		Value:    types.StringValue("sip.example.com"),
		Priority: types.Int64Value(10),
		Weight:   types.Int64Value(60),
		Port:     types.Int64Value(5060),
	}
	if !recordMatchesState(rec, state) {
		t.Error("expected match for identical SRV record")
	}
}

func TestRecordMatchesState_SRV_DifferentPort(t *testing.T) {
	rec := client.Record{
		Type: "SRV",
		RData: map[string]interface{}{
			"target":   "sip.example.com",
			"priority": float64(10),
			"weight":   float64(60),
			"port":     float64(5061),
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("SRV"),
		Value:    types.StringValue("sip.example.com"),
		Priority: types.Int64Value(10),
		Weight:   types.Int64Value(60),
		Port:     types.Int64Value(5060),
	}
	if recordMatchesState(rec, state) {
		t.Error("expected no match for SRV with different port")
	}
}

func TestRecordMatchesState_CAA_Match(t *testing.T) {
	rec := client.Record{
		Type: "CAA",
		RData: map[string]interface{}{
			"value": "letsencrypt.org",
			"flags": float64(0),
			"tag":   "issue",
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("CAA"),
		Value:    types.StringValue("letsencrypt.org"),
		CAAFlags: types.Int64Value(0),
		CAATag:   types.StringValue("issue"),
	}
	if !recordMatchesState(rec, state) {
		t.Error("expected match for identical CAA record")
	}
}

func TestRecordMatchesState_CAA_DifferentTag(t *testing.T) {
	rec := client.Record{
		Type: "CAA",
		RData: map[string]interface{}{
			"value": "letsencrypt.org",
			"flags": float64(0),
			"tag":   "issuewild",
		},
	}
	state := &RecordResourceModel{
		Type:     types.StringValue("CAA"),
		Value:    types.StringValue("letsencrypt.org"),
		CAAFlags: types.Int64Value(0),
		CAATag:   types.StringValue("issue"),
	}
	if recordMatchesState(rec, state) {
		t.Error("expected no match for CAA with different tag")
	}
}

func TestRecordMatchesState_TXT(t *testing.T) {
	rec := client.Record{
		Type: "TXT",
		RData: map[string]interface{}{
			"text": "v=spf1 include:_spf.google.com ~all",
		},
	}
	state := &RecordResourceModel{
		Type:  types.StringValue("TXT"),
		Value: types.StringValue("v=spf1 include:_spf.google.com ~all"),
	}
	if !recordMatchesState(rec, state) {
		t.Error("expected match for identical TXT record")
	}
}
