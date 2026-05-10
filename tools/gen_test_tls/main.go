// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

// gen_test_tls generates a self-signed CA and a server certificate suitable
// for use by the acceptance-test Technitium DNS Server container and for
// the Terraform provider's ca_cert_file attribute. It is invoked by the
// `make testacc-tls-prep` target before the Technitium container is started.
//
// Outputs (written to the directory passed via -out):
//
//	ca.pem      PEM-encoded self-signed CA certificate. Pass to the provider
//	            via TECHNITIUM_CACERT or ca_cert_file so the test client
//	            trusts the server cert.
//	ca.key      PEM-encoded CA private key. Retained only so that the same
//	            CA can re-issue a server cert without rolling the CA root,
//	            if a future test target wants that.
//	server.pfx  PKCS#12 bundle containing the server certificate, its
//	            private key, and the CA certificate as a chain entry.
//	            Mounted into the Technitium container and pointed at by the
//	            DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH env var.
//	server.crt  PEM-encoded server certificate. For debugging only.
//	server.key  PEM-encoded server private key. For debugging only.
//
// All keys are ECDSA P-384 to satisfy the provider's NSS-mode FIPS
// expectations. Certificate validity is short (default 24h) because the
// material is regenerated on every test run; nothing here should ever
// reach a non-test environment.
//
// Usage:
//
//	go run ./tools/gen_test_tls \
//	    -out ./testdata/tls \
//	    -hosts 127.0.0.1,localhost \
//	    -pfx-password test
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func main() {
	outDir := flag.String("out", "./testdata/tls", "Output directory for generated TLS material")
	hostList := flag.String("hosts", "127.0.0.1,localhost", "Comma-separated list of DNS names and/or IPs the server cert should cover")
	durationFlag := flag.Duration("duration", 24*time.Hour, "Certificate validity duration")
	pfxPassword := flag.String("pfx-password", "test", "Password used to encrypt the PKCS#12 bundle. Technitium requires a non-empty password.")
	flag.Parse()

	if err := run(*outDir, *hostList, *durationFlag, *pfxPassword); err != nil {
		log.Fatalf("gen_test_tls: %s", err)
	}
}

func run(outDir, hostList string, validity time.Duration, pfxPassword string) error {
	if pfxPassword == "" {
		return fmt.Errorf("-pfx-password must not be empty (Technitium requires a password-protected PKCS#12 bundle)")
	}
	// 5 minutes covers the cert backdating window in mintCA / mintServer.
	// Anything shorter produces a cert whose NotBefore is later than NotAfter
	// (i.e. immediately expired), which surfaces as confusing TLS handshake
	// errors at test time.
	if validity <= 5*time.Minute {
		return fmt.Errorf("-duration must be greater than 5m (got %s) — short windows collide with the cert backdating offset", validity)
	}
	// 0750 is the strictest mode gosec G301 will accept for a directory.
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("creating output directory %q: %w", outDir, err)
	}

	dnsNames, ipAddrs, err := splitHosts(hostList)
	if err != nil {
		return err
	}
	if len(dnsNames) == 0 && len(ipAddrs) == 0 {
		return fmt.Errorf("at least one host (DNS name or IP) must be supplied via -hosts")
	}

	now := time.Now().UTC()

	caKey, caCert, caDER, err := mintCA(now, validity)
	if err != nil {
		return fmt.Errorf("minting CA: %w", err)
	}

	serverKey, _, serverDER, err := mintServer(now, validity, dnsNames, ipAddrs, caCert, caKey)
	if err != nil {
		return fmt.Errorf("minting server cert: %w", err)
	}

	caCertParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parsing CA DER: %w", err)
	}
	serverCertParsed, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return fmt.Errorf("parsing server DER: %w", err)
	}

	// Encode PKCS#12 bundle for the Technitium container. Modern algorithms
	// are required by Technitium's underlying .NET runtime; pkcs12.Modern
	// produces an AES-256-CBC encrypted bundle compatible with .NET 8+.
	pfxBytes, err := pkcs12.Modern.Encode(serverKey, serverCertParsed, []*x509.Certificate{caCertParsed}, pfxPassword)
	if err != nil {
		return fmt.Errorf("encoding PKCS#12: %w", err)
	}

	files := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{"ca.pem", 0o644, pemEncode("CERTIFICATE", caDER)},
		{"ca.key", 0o600, pemEncodeECKey(caKey)},
		{"server.crt", 0o644, pemEncode("CERTIFICATE", serverDER)},
		{"server.key", 0o600, pemEncodeECKey(serverKey)},
		{"server.pfx", 0o600, pfxBytes},
	}
	for _, f := range files {
		path := filepath.Join(outDir, f.name)
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", path)
	}

	return nil
}

func mintCA(now time.Time, validity time.Duration) (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"terraform-provider-technitium test CA"},
			CommonName:   "terraform-provider-technitium-test-ca",
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, template, der, nil
}

func mintServer(now time.Time, validity time.Duration, dnsNames []string, ipAddrs []net.IP, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	cn := "127.0.0.1"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"terraform-provider-technitium test server"},
			CommonName:   cn,
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, template, der, nil
}

func splitHosts(hosts string) ([]string, []net.IP, error) {
	var dns []string
	var ips []net.IP
	for _, raw := range strings.Split(hosts, ",") {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, h)
	}
	return dns, ips, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func pemEncodeECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		// Should never happen for a freshly-minted ECDSA P-384 key.
		panic(fmt.Sprintf("marshalling EC private key: %s", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
