// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

func TestClusterSecondaryNodeClient_RedactsNodeURL(t *testing.T) {
	r := &ClusterSecondaryResource{}
	model := &ClusterSecondaryResourceModel{
		NodeURL:            types.StringValue("http://user:hunter2@127.0.0.1:1"),
		NodeUsername:       types.StringValue("admin"),
		NodePassword:       types.StringValue("pass"),
		JoinTimeoutSeconds: types.Int64Value(1),
	}
	_, err := r.nodeClient(context.Background(), model)
	if err == nil {
		t.Fatal("expected login against a closed port to fail")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "user:") {
		t.Errorf("error leaks node_url userinfo: %v", err)
	}
}

func TestConnectFailureHelpers_HTTPSDetectionAndRedaction(t *testing.T) {
	if d := tlsConnectionDiagnostic("HTTPS://user:hunter2@dns.example.test:53443", x509.UnknownAuthorityError{}, false, false); d == "" {
		t.Error("uppercase HTTPS:// should get the TLS diagnostic")
	} else if strings.Contains(d, "hunter2") {
		t.Errorf("TLS diagnostic leaks userinfo: %s", d)
	}
	if d := tlsConnectionDiagnostic("http://dns.example.test:5380", x509.UnknownAuthorityError{}, false, false); d != "" {
		t.Errorf("http:// should not get a TLS diagnostic, got %q", d)
	}
	if msg := loginFailureDetail("http://user:hunter2@dns.example.test:5380", "admin", errors.New("refused")); strings.Contains(msg, "hunter2") || strings.Contains(msg, "user:") {
		t.Errorf("login detail leaks userinfo: %s", msg)
	}
}
