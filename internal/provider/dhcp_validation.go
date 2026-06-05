// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.ResourceWithValidateConfig = &DHCPScopeResource{}
	_ resource.ResourceWithValidateConfig = &DHCPReservedLeaseResource{}
)

// ValidateConfig checks DHCP scope addressing invariants at plan time.
// Unknown values (interpolations not yet resolved) are skipped.
func (r *DHCPScopeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config DHCPScopeResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	start := validateIPv4Attr(config.StartingAddress, path.Root("starting_address"), &resp.Diagnostics)
	end := validateIPv4Attr(config.EndingAddress, path.Root("ending_address"), &resp.Diagnostics)
	validateSubnetMaskAttr(config.SubnetMask, path.Root("subnet_mask"), &resp.Diagnostics)

	if start != nil && end != nil && ipv4ToUint(start) > ipv4ToUint(end) {
		resp.Diagnostics.AddAttributeError(path.Root("starting_address"),
			"Invalid scope range",
			fmt.Sprintf("starting_address %s is after ending_address %s.", start, end))
	}

	for i, excl := range config.Exclusions {
		p := path.Root("exclusions").AtListIndex(i)
		exclStart := validateIPv4Attr(excl.StartingAddress, p.AtName("starting_address"), &resp.Diagnostics)
		exclEnd := validateIPv4Attr(excl.EndingAddress, p.AtName("ending_address"), &resp.Diagnostics)
		if exclStart != nil && exclEnd != nil && ipv4ToUint(exclStart) > ipv4ToUint(exclEnd) {
			resp.Diagnostics.AddAttributeError(p.AtName("starting_address"),
				"Invalid exclusion range",
				fmt.Sprintf("exclusion starting_address %s is after ending_address %s.", exclStart, exclEnd))
		}
		if start != nil && end != nil && exclStart != nil && exclEnd != nil {
			if ipv4ToUint(exclStart) < ipv4ToUint(start) || ipv4ToUint(exclEnd) > ipv4ToUint(end) {
				resp.Diagnostics.AddAttributeError(p,
					"Exclusion outside scope range",
					fmt.Sprintf("exclusion %s-%s is not contained in the scope range %s-%s.", exclStart, exclEnd, start, end))
			}
		}
	}

	for i, route := range config.StaticRoutes {
		p := path.Root("static_routes").AtListIndex(i)
		validateIPv4Attr(route.Destination, p.AtName("destination"), &resp.Diagnostics)
		validateSubnetMaskAttr(route.SubnetMask, p.AtName("subnet_mask"), &resp.Diagnostics)
		validateIPv4Attr(route.Router, p.AtName("router"), &resp.Diagnostics)
	}

	for i, lease := range config.ReservedLeases {
		p := path.Root("reserved_leases").AtListIndex(i)
		validateMACAttr(lease.HardwareAddress, p.AtName("hardware_address"), &resp.Diagnostics)
		addr := validateIPv4Attr(lease.Address, p.AtName("address"), &resp.Diagnostics)
		if start != nil && end != nil && addr != nil &&
			(ipv4ToUint(addr) < ipv4ToUint(start) || ipv4ToUint(addr) > ipv4ToUint(end)) {
			resp.Diagnostics.AddAttributeError(p.AtName("address"),
				"Reservation outside scope range",
				fmt.Sprintf("reserved address %s is not contained in the scope range %s-%s.", addr, start, end))
		}
	}
}

// ValidateConfig checks reservation MAC and IP formats at plan time.
func (r *DHCPReservedLeaseResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config DHCPReservedLeaseResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateMACAttr(config.HardwareAddress, path.Root("hardware_address"), &resp.Diagnostics)
	validateIPv4Attr(config.IPAddress, path.Root("ip_address"), &resp.Diagnostics)
}

// validateIPv4Attr parses a types.String as an IPv4 address, appending a
// diagnostic on failure. Returns nil for null/unknown/invalid values.
func validateIPv4Attr(v types.String, p path.Path, diags *diag.Diagnostics) net.IP {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	ip := net.ParseIP(v.ValueString())
	if ip == nil || ip.To4() == nil {
		diags.AddAttributeError(p, "Invalid IPv4 address",
			fmt.Sprintf("%q is not a valid IPv4 address.", v.ValueString()))
		return nil
	}
	return ip.To4()
}

// validateSubnetMaskAttr parses a types.String as a contiguous IPv4 netmask.
func validateSubnetMaskAttr(v types.String, p path.Path, diags *diag.Diagnostics) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	ip := net.ParseIP(v.ValueString())
	if ip == nil || ip.To4() == nil {
		diags.AddAttributeError(p, "Invalid subnet mask",
			fmt.Sprintf("%q is not a valid IPv4 subnet mask.", v.ValueString()))
		return
	}
	mask := net.IPMask(ip.To4())
	if ones, bits := mask.Size(); ones == 0 && bits == 0 {
		diags.AddAttributeError(p, "Invalid subnet mask",
			fmt.Sprintf("%q is not a contiguous IPv4 subnet mask.", v.ValueString()))
	}
}

// validateMACAttr parses a types.String as a MAC address.
func validateMACAttr(v types.String, p path.Path, diags *diag.Diagnostics) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	if _, err := net.ParseMAC(v.ValueString()); err != nil {
		diags.AddAttributeError(p, "Invalid MAC address",
			fmt.Sprintf("%q is not a valid MAC address (expected e.g. 00-11-22-33-44-55).", v.ValueString()))
	}
}

// ipv4ToUint converts a 4-byte IP to a comparable integer.
func ipv4ToUint(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}
