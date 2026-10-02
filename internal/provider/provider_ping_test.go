// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"strings"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

// A Technitium server older than 15.0 ignores the Authorization: Bearer
// header, so under the default auth mode every request fails as
// invalid-token. The connect diagnostic must point the operator at
// legacy_token_auth instead of leaving them to guess.
func TestPingFailureDetail_InvalidTokenHintsLegacyAuth(t *testing.T) {
	invalid := &client.APIError{Status: "invalid-token", ErrorMessage: "Invalid token or session expired."}

	got := pingFailureDetail("https://dns.example.com:53443", invalid, false)
	if !strings.Contains(got, "legacy_token_auth") {
		t.Errorf("default-auth invalid-token detail lacks the legacy_token_auth hint:\n%s", got)
	}
	if !strings.Contains(got, invalid.Error()) {
		t.Errorf("detail dropped the underlying error:\n%s", got)
	}
}

func TestPingFailureDetail_NoHintWhenNotApplicable(t *testing.T) {
	cases := map[string]struct {
		err    error
		legacy bool
	}{
		"already legacy":    {&client.APIError{Status: "invalid-token"}, true},
		"other API error":   {&client.APIError{Status: "error", ErrorMessage: "boom"}, false},
		"transport failure": {errors.New("dial tcp: connection refused"), false},
	}
	for name, tc := range cases {
		got := pingFailureDetail("https://dns.example.com:53443", tc.err, tc.legacy)
		if strings.Contains(got, "legacy_token_auth") {
			t.Errorf("%s: unexpected legacy_token_auth hint:\n%s", name, got)
		}
	}
}
