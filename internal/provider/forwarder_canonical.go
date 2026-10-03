// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var forwarderPortPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
var forwarderDigitsAndDots = regexp.MustCompile(`^[0-9.]+$`)

func canonicalForwarder(input, protocol string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" || strings.Contains(s, ",") {
		return "", fmt.Errorf("forwarder %q must be a single address", input)
	}
	switch protocol {
	case "Udp", "Tcp", "Tls", "Https", "Quic":
	default:
		return "", fmt.Errorf("unsupported forwarder_protocol %q", protocol)
	}
	udp := protocol == "Udp"

	base, suffix := s, ""
	if i := strings.LastIndex(s, " ("); i > 0 && strings.HasSuffix(s, ")") {
		base, suffix = s[:i], s[i:]
		addr, err := netip.ParseAddr(suffix[2 : len(suffix)-1])
		if err != nil || addr.Zone() != "" {
			return "", fmt.Errorf("forwarder %q: the address in parentheses must be an IP address", input)
		}
		if !udp {
			if addr.Is6() && !addr.Is4In6() {
				suffix = " ([" + addr.String() + "])"
			} else {
				suffix = " (" + addr.String() + ")"
			}
		}
	}
	if !udp {
		base = strings.TrimRight(base, " ")
	}

	if strings.HasPrefix(strings.ToLower(base), "https://") {
		if protocol != "Https" {
			return "", fmt.Errorf("forwarder %q is a DNS-over-HTTPS URL but forwarder_protocol is %s; use a host or host:port", input, protocol)
		}
		u, err := url.Parse(base)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("forwarder %q is not a valid DNS-over-HTTPS URL", input)
		}
		return base + suffix, nil
	}

	host, port, err := splitForwarderHostPort(base)
	if err != nil {
		return "", fmt.Errorf("forwarder %q: %w", input, err)
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if !forwarderPortPattern.MatchString(port) || err != nil || n > 65535 {
			return "", fmt.Errorf("forwarder %q: invalid port %q", input, port)
		}
	}
	if (port == "53" && protocol != "Udp" && protocol != "Tcp") || (port == "853" && protocol != "Tls" && protocol != "Quic") {
		return "", fmt.Errorf("forwarder %q: port %s is not used with forwarder_protocol %s; remove the port or use the protocol's port", input, port, protocol)
	}
	if port == "53" || port == "853" || (protocol == "Https" && port == "443") {
		port = ""
	}

	if !udp {
		if strings.Contains(host, "%") {
			return "", fmt.Errorf("forwarder %q: IPv6 zone identifiers are not supported with forwarder_protocol %s", input, protocol)
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			host = addr.String()
		} else if forwarderDigitsAndDots.MatchString(host) {
			return "", fmt.Errorf("forwarder %q: %q is not a valid IPv4 address", input, host)
		}
	}

	v6 := strings.Contains(host, ":")
	bracketed := host
	if v6 {
		bracketed = "[" + host + "]"
	}

	var out string
	switch protocol {
	case "Udp":
		out = host
		if port != "" {
			out = bracketed + ":" + port
		}
	case "Tcp":
		out = bracketed
		if port != "" {
			out += ":" + port
		}
	case "Tls", "Quic":
		if port == "" {
			port = "853"
		}
		out = bracketed + ":" + port
	case "Https":
		out = "https://" + strings.ToLower(bracketed)
		if port != "" {
			out += ":" + port
		}
		out += "/dns-query"
	}
	return out + suffix, nil
}

func splitForwarderHostPort(s string) (string, string, error) {
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", errors.New("unclosed IPv6 bracket")
		}
		host, rest := s[1:end], s[end+1:]
		if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
			return "", "", errors.New("brackets are only allowed around an IPv6 address")
		}
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", errors.New("unexpected text after IPv6 address")
		}
		return host, rest[1:], nil
	case strings.Count(s, ":") > 1:
		return s, "", nil
	case strings.Contains(s, ":"):
		host, port, _ := strings.Cut(s, ":")
		if host == "" {
			return "", "", errors.New("missing host")
		}
		return host, port, nil
	default:
		return s, "", nil
	}
}
