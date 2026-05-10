// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestSplitHosts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantDNS []string
		wantIPs []string // string form for stable comparison
	}{
		{"single dns", "localhost", []string{"localhost"}, nil},
		{"single ipv4", "127.0.0.1", nil, []string{"127.0.0.1"}},
		{"single ipv6", "::1", nil, []string{"::1"}},
		{"mixed", "127.0.0.1,localhost,::1,host.example.internal", []string{"localhost", "host.example.internal"}, []string{"127.0.0.1", "::1"}},
		{"with spaces", " 127.0.0.1 , localhost ", []string{"localhost"}, []string{"127.0.0.1"}},
		{"empty entries skipped", "127.0.0.1,,localhost,,", []string{"localhost"}, []string{"127.0.0.1"}},
		{"empty input", "", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dns, ips, err := splitHosts(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if !equalStrings(dns, tc.wantDNS) {
				t.Errorf("dns mismatch: want %v, got %v", tc.wantDNS, dns)
			}
			ipStrs := make([]string, len(ips))
			for i, ip := range ips {
				ipStrs[i] = ip.String()
			}
			if !equalStrings(ipStrs, tc.wantIPs) {
				t.Errorf("ips mismatch: want %v, got %v", tc.wantIPs, ipStrs)
			}
		})
	}
}

func TestRun_RejectsEmptyPassword(t *testing.T) {
	err := run(t.TempDir(), "127.0.0.1", time.Hour, "")
	if err == nil {
		t.Fatal("expected error for empty -pfx-password, got nil")
	}
}

func TestRun_RejectsShortDuration(t *testing.T) {
	err := run(t.TempDir(), "127.0.0.1", 4*time.Minute, "test")
	if err == nil {
		t.Fatal("expected error for duration shorter than the cert backdating window")
	}
}

func TestRun_RejectsEmptyHosts(t *testing.T) {
	err := run(t.TempDir(), "  , ,", time.Hour, "test")
	if err == nil {
		t.Fatal("expected error when no hosts resolve from -hosts input")
	}
}

func TestRun_ProducesValidMaterial(t *testing.T) {
	out := t.TempDir()
	const password = "test"
	const validity = time.Hour

	if err := run(out, "127.0.0.1,localhost", validity, password); err != nil {
		t.Fatalf("run failed: %s", err)
	}

	// Files exist with the expected modes.
	for _, want := range []struct {
		name string
		mode os.FileMode
	}{
		{"ca.pem", 0o644},
		{"ca.key", 0o600},
		{"server.crt", 0o644},
		{"server.key", 0o600},
		{"server.pfx", 0o600},
	} {
		path := filepath.Join(out, want.name)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing file %s: %s", want.name, err)
		}
		if fi.Mode().Perm() != want.mode {
			t.Errorf("%s: mode = %v, want %v", want.name, fi.Mode().Perm(), want.mode)
		}
	}

	// CA must be self-signed (issuer == subject).
	caCert := mustParsePEM(t, filepath.Join(out, "ca.pem"))
	if caCert.Subject.String() != caCert.Issuer.String() {
		t.Errorf("CA is not self-signed: subject %q != issuer %q", caCert.Subject, caCert.Issuer)
	}
	if !caCert.IsCA {
		t.Error("CA cert does not have IsCA=true")
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert does not have KeyUsage CertSign")
	}

	// Server cert chain validates against the CA, has the right SAN, EKU, KU.
	serverCert := mustParsePEM(t, filepath.Join(out, "server.crt"))
	if serverCert.Issuer.String() != caCert.Subject.String() {
		t.Errorf("server cert not issued by CA: issuer %q, CA subject %q", serverCert.Issuer, caCert.Subject)
	}
	if serverCert.IsCA {
		t.Error("server cert unexpectedly has IsCA=true")
	}
	wantDNS := []string{"localhost"}
	gotDNS := append([]string(nil), serverCert.DNSNames...)
	sort.Strings(gotDNS)
	if !reflect.DeepEqual(gotDNS, wantDNS) {
		t.Errorf("server cert DNSNames: want %v, got %v", wantDNS, gotDNS)
	}
	wantIP := net.ParseIP("127.0.0.1")
	foundIP := false
	for _, ip := range serverCert.IPAddresses {
		if ip.Equal(wantIP) {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Errorf("server cert IP SAN missing 127.0.0.1: got %v", serverCert.IPAddresses)
	}
	if !hasExtKeyUsage(serverCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Error("server cert missing ExtKeyUsageServerAuth")
	}
	if serverCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("server cert missing KeyUsage DigitalSignature")
	}

	// Validity window: not-before is in the past (backdating), not-after is in the future.
	now := time.Now()
	if !serverCert.NotBefore.Before(now) {
		t.Errorf("server cert NotBefore %s is not in the past relative to %s", serverCert.NotBefore, now)
	}
	if !serverCert.NotAfter.After(now) {
		t.Errorf("server cert NotAfter %s is not in the future relative to %s", serverCert.NotAfter, now)
	}
	// Independently confirm the chain validates.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server cert chain verification failed: %s", err)
	}

	// PKCS12 decodes with the supplied password and contains the same server cert.
	pfxBytes, err := os.ReadFile(filepath.Join(out, "server.pfx"))
	if err != nil {
		t.Fatalf("reading server.pfx: %s", err)
	}
	_, decodedCert, decodedCAs, err := pkcs12.DecodeChain(pfxBytes, password)
	if err != nil {
		t.Fatalf("decoding server.pfx: %s", err)
	}
	if decodedCert.SerialNumber.Cmp(serverCert.SerialNumber) != 0 {
		t.Error("PKCS12 server cert serial does not match server.crt")
	}
	if len(decodedCAs) != 1 || decodedCAs[0].SerialNumber.Cmp(caCert.SerialNumber) != 0 {
		t.Error("PKCS12 chain does not contain the CA")
	}

	// Wrong password is rejected.
	if _, _, _, err := pkcs12.DecodeChain(pfxBytes, "wrong"); err == nil {
		t.Error("PKCS12 decode with wrong password unexpectedly succeeded")
	}
}

func mustParsePEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %s", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %s", path, err)
	}
	return cert
}

func hasExtKeyUsage(usages []x509.ExtKeyUsage, target x509.ExtKeyUsage) bool {
	for _, u := range usages {
		if u == target {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}
