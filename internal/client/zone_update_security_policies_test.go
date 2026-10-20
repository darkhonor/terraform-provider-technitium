// Copyright (c) 2026 Max Pfeiffer
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

func TestFormatUpdateSecurityPolicies(t *testing.T) {
	tests := []struct {
		name     string
		policies []UpdateSecurityPolicy
		want     string
	}{
		{
			name:     "nil clears the policies",
			policies: nil,
			want:     "false",
		},
		{
			name:     "empty clears the policies",
			policies: []UpdateSecurityPolicy{},
			want:     "false",
		},
		{
			name: "single policy",
			policies: []UpdateSecurityPolicy{
				{TsigKeyName: "acme", Domain: "*.example.internal", AllowedTypes: []string{"TXT"}},
			},
			want: "acme|*.example.internal|TXT",
		},
		{
			name: "rows keep their order and types are comma separated",
			policies: []UpdateSecurityPolicy{
				{TsigKeyName: "key-b", Domain: "example.internal", AllowedTypes: []string{"A", "AAAA"}},
				{TsigKeyName: "key-a", Domain: "*.example.internal", AllowedTypes: []string{"TXT"}},
			},
			want: "key-b|example.internal|A,AAAA|key-a|*.example.internal|TXT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatUpdateSecurityPolicies(tt.policies); got != tt.want {
				t.Fatalf("FormatUpdateSecurityPolicies() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The formatted policies must reach /api/zones/options/set unmodified.
func TestZoneOptionsSet_UpdateSecurityPoliciesParam(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/zones/options/set" {
			_ = r.ParseForm()
			got = r.PostForm
		}
		_, _ = fmt.Fprint(w, `{"status":"ok"}`)
	})
	defer srv.Close()

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	value := FormatUpdateSecurityPolicies([]UpdateSecurityPolicy{
		{TsigKeyName: "acme", Domain: "*.example.internal", AllowedTypes: []string{"TXT"}},
	})
	if err := c.ZoneOptionsSet(context.Background(), "example.internal", map[string]string{
		"updateSecurityPolicies": value,
	}); err != nil {
		t.Fatalf("ZoneOptionsSet: %v", err)
	}

	if got.Get("updateSecurityPolicies") != "acme|*.example.internal|TXT" {
		t.Fatalf("updateSecurityPolicies = %q (all params: %v)", got.Get("updateSecurityPolicies"), got)
	}
}

// ZoneOptionsGet must surface the policies in the format the server reports.
func TestZoneOptionsGet_ParsesUpdateSecurityPolicies(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"status":"ok","response":{
			"name":"example.internal",
			"type":"Primary",
			"update":"UseSpecifiedNetworkACL",
			"updateNetworkACL":["192.0.2.0/24"],
			"updateSecurityPolicies":[
				{"tsigKeyName":"key-a","domain":"*.example.internal","allowedTypes":["TXT"]},
				{"tsigKeyName":"key-b","domain":"example.internal","allowedTypes":["A","AAAA"]}
			]
		}}`)
	})
	defer srv.Close()

	c, err := NewClient(ClientConfig{BaseURL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	z, err := c.ZoneOptionsGet(context.Background(), "example.internal")
	if err != nil {
		t.Fatalf("ZoneOptionsGet: %v", err)
	}

	want := []UpdateSecurityPolicy{
		{TsigKeyName: "key-a", Domain: "*.example.internal", AllowedTypes: []string{"TXT"}},
		{TsigKeyName: "key-b", Domain: "example.internal", AllowedTypes: []string{"A", "AAAA"}},
	}
	if !reflect.DeepEqual(z.UpdateSecurityPolicies, want) {
		t.Fatalf("UpdateSecurityPolicies = %+v, want %+v", z.UpdateSecurityPolicies, want)
	}
}
