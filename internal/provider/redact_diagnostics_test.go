// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"strings"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
)

func TestDiagnostics_RedactUserinfoInServerURL(t *testing.T) {
	const serverURL = "https://user:hunter2@dns.example.test:53443"
	msgs := map[string]string{
		"ping": pingFailureDetail(serverURL, errors.New("connection refused"), false),
	}
	for name, kind := range map[string]client.TLSErrorKind{
		"tls-version":   client.TLSErrVersionMismatch,
		"tls-authority": client.TLSErrUnknownAuthority,
		"tls-invalid":   client.TLSErrCertificateInvalid,
	} {
		msgs[name] = buildTLSDiagnostic(client.TLSError{Kind: kind}, serverURL, false, false)
	}
	for name, msg := range msgs {
		if strings.Contains(msg, "hunter2") || strings.Contains(msg, "user:") {
			t.Errorf("%s diagnostic leaks userinfo: %s", name, msg)
		}
	}
}
