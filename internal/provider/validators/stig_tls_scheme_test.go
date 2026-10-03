// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package validators

import (
	"context"
	"testing"
)

func TestValidateTLSEnabled_SchemeIsCaseInsensitive(t *testing.T) {
	cases := map[string]bool{
		"https://dns.example.test:53443": true,
		"HTTPS://dns.example.test:53443": true,
		"http://dns.example.test:5380":   false,
	}
	for serverURL, want := range cases {
		got := validateTLSEnabled(context.Background(), NewMockAccessor(map[string]interface{}{"server_url": serverURL}))
		if got != want {
			t.Errorf("%s: validateTLSEnabled = %v, want %v", serverURL, got, want)
		}
	}
}
