// Copyright (c) 2026 Tristan Milnthorp
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Zone types that pull their data from primary name servers.
//
//   - primary_name_server_addresses applies to the Secondary family and Stub
//     (for a Stub it is the server queried for the zone's NS records).
//   - zone_transfer_protocol applies to the Secondary family only: Technitium
//     does not report or accept a transfer protocol for Stub zones.
const (
	zoneTypeSecondary          = "Secondary"
	zoneTypeSecondaryForwarder = "SecondaryForwarder"
	zoneTypeSecondaryCatalog   = "SecondaryCatalog"
	zoneTypeStub               = "Stub"
)

// isSecondaryFamilyZoneType reports whether the zone type transfers from a
// primary using a transfer protocol.
func isSecondaryFamilyZoneType(zoneType string) bool {
	switch zoneType {
	case zoneTypeSecondary, zoneTypeSecondaryForwarder, zoneTypeSecondaryCatalog:
		return true
	}
	return false
}

// takesPrimaryNameServers reports whether primary_name_server_addresses is
// meaningful for the zone type.
func takesPrimaryNameServers(zoneType string) bool {
	return isSecondaryFamilyZoneType(zoneType) || zoneType == zoneTypeStub
}

// canonicalPrimaryAddress reduces a primary name server address to a form that
// compares equal to the one Technitium echoes back.
//
// Verified against a running server: with the Tls or Quic protocol the server
// stores and returns "10.0.0.1" as "10.0.0.1:853", and it brackets bare IPv6
// literals ("2001:db8::1" -> "[2001:db8::1]"). The configured value must be
// kept in state when it means the same thing, otherwise Terraform reports
// "Provider produced inconsistent result after apply" or a perpetual diff.
func canonicalPrimaryAddress(addr, protocol string) string {
	addr = strings.TrimSpace(addr)
	host, port := addr, ""
	switch {
	case strings.HasPrefix(addr, "["):
		if end := strings.Index(addr, "]"); end > 0 {
			host = addr[1:end]
			port = strings.TrimPrefix(addr[end+1:], ":")
		}
	case strings.Count(addr, ":") == 1:
		host, port, _ = strings.Cut(addr, ":")
	}
	if port == "" {
		port = "53"
		if protocol == "Tls" || protocol == "Quic" {
			port = "853"
		}
	}
	return strings.ToLower(host) + "|" + port
}

// samePrimaryAddresses reports whether two address lists are equivalent, in
// order, once the server's normalisation is accounted for. Order is
// significant: the list is the primaries' order of preference.
func samePrimaryAddresses(a, b []string, protocol string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if canonicalPrimaryAddress(a[i], protocol) != canonicalPrimaryAddress(b[i], protocol) {
			return false
		}
	}
	return true
}

// resolvePrimaryAddresses chooses what to store for primary_name_server_addresses
// after a read. When the prior value (plan or state) is equivalent to what the
// server reports, the prior value is kept verbatim so the configuration does
// not show a diff for server-side normalisation. Otherwise the server's value
// wins, which is what surfaces genuine drift and populates an import.
func resolvePrimaryAddresses(ctx context.Context, prior types.List, server []string, protocol string) types.List {
	if len(server) == 0 {
		return types.ListNull(types.StringType)
	}
	if !prior.IsNull() && !prior.IsUnknown() {
		var priorAddrs []string
		if diags := prior.ElementsAs(ctx, &priorAddrs, false); !diags.HasError() &&
			samePrimaryAddresses(priorAddrs, server, protocol) {
			return prior
		}
	}
	list, diags := types.ListValueFrom(ctx, types.StringType, server)
	if diags.HasError() {
		return types.ListNull(types.StringType)
	}
	return list
}
