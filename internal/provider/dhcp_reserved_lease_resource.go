// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &DHCPReservedLeaseResource{}
	_ resource.ResourceWithImportState = &DHCPReservedLeaseResource{}
)

func NewDHCPReservedLeaseResource() resource.Resource {
	return &DHCPReservedLeaseResource{}
}

// DHCPReservedLeaseResource manages a single MAC-to-IP reservation in a DHCP scope.
type DHCPReservedLeaseResource struct {
	client *client.Client
}

// DHCPReservedLeaseResourceModel describes the resource data model.
type DHCPReservedLeaseResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Scope           types.String `tfsdk:"scope"`
	HardwareAddress types.String `tfsdk:"hardware_address"`
	IPAddress       types.String `tfsdk:"ip_address"`
	HostName        types.String `tfsdk:"host_name"`
	Comments        types.String `tfsdk:"comments"`
}

func (r *DHCPReservedLeaseResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_reserved_lease"
}

func (r *DHCPReservedLeaseResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a single MAC-to-IP reservation in a Technitium DHCP scope. " +
			"Do not combine with inline reserved_leases on the same technitium_dhcp_scope — " +
			"the two would fight over the same server-side list.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Reservation identifier (scope::hardware_address composite).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"scope": schema.StringAttribute{
				Description: "Name of the DHCP scope holding the reservation.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"hardware_address": schema.StringAttribute{
				Description: "Client MAC address (e.g. 00-11-22-33-44-55).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ip_address": schema.StringAttribute{
				Description: "Reserved IP address inside the scope range.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"host_name": schema.StringAttribute{
				Description: "Host name override for the client.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"comments": schema.StringAttribute{
				Description: "Free-form comments for the reservation.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *DHCPReservedLeaseResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	r.client = providerData.Client
}

func (r *DHCPReservedLeaseResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DHCPReservedLeaseResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	lease := client.DHCPReservedLease{
		HardwareAddress: plan.HardwareAddress.ValueString(),
		Address:         plan.IPAddress.ValueString(),
		HostName:        plan.HostName.ValueString(),
		Comments:        plan.Comments.ValueString(),
	}
	if err := r.client.DHCPScopeAddReservedLease(ctx, plan.Scope.ValueString(), lease); err != nil {
		resp.Diagnostics.AddError("Error creating DHCP reserved lease", err.Error())
		return
	}

	plan.ID = types.StringValue(dhcpReservedLeaseID(plan.Scope.ValueString(), plan.HardwareAddress.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPReservedLeaseResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DHCPReservedLeaseResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, err := r.client.DHCPScopeGet(ctx, state.Scope.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrDHCPScopeNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading DHCP scope for reserved lease", err.Error())
		return
	}

	lease, found := findReservedLease(scope.ReservedLeases, state.HardwareAddress.ValueString())
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(dhcpReservedLeaseID(state.Scope.ValueString(), state.HardwareAddress.ValueString()))
	state.IPAddress = types.StringValue(lease.Address)
	// Keep the configured MAC formatting; the server normalizes separators.
	if !macEqual(state.HardwareAddress.ValueString(), lease.HardwareAddress) {
		state.HardwareAddress = types.StringValue(lease.HardwareAddress)
	}
	state.HostName = stringOrNull(lease.HostName)
	state.Comments = stringOrNull(lease.Comments)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is never called: every attribute is RequiresReplace, so changes go
// through Delete+Create. The method exists to satisfy the Resource interface.
func (r *DHCPReservedLeaseResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

func (r *DHCPReservedLeaseResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DHCPReservedLeaseResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DHCPScopeRemoveReservedLease(ctx, state.Scope.ValueString(), state.HardwareAddress.ValueString())
	if err != nil {
		// Scope (and with it the reservation) already gone is fine.
		var apiErr *client.APIError
		if errors.As(err, &apiErr) {
			msg := strings.ToLower(apiErr.ErrorMessage)
			if strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist") {
				return
			}
		}
		resp.Diagnostics.AddError("Error deleting DHCP reserved lease", err.Error())
	}
}

func (r *DHCPReservedLeaseResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// ID format: <scope>::<hardware address>
	scope, mac, ok := strings.Cut(req.ID, "::")
	if !ok || scope == "" || mac == "" {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Expected import ID in the form \"<scope>::<hardware address>\", got: %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("scope"), scope)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("hardware_address"), mac)...)
}

// dhcpReservedLeaseID builds the composite resource ID.
func dhcpReservedLeaseID(scope, mac string) string {
	return scope + "::" + mac
}

// macEqual compares MAC addresses ignoring case and -/: separator differences.
func macEqual(a, b string) bool {
	return normalizeMAC(a) == normalizeMAC(b)
}

func normalizeMAC(mac string) string {
	mac = strings.ToUpper(mac)
	mac = strings.ReplaceAll(mac, ":", "-")
	return mac
}

// findReservedLease locates a reservation by MAC in a scope's reservation list.
func findReservedLease(leases []client.DHCPReservedLease, mac string) (client.DHCPReservedLease, bool) {
	for _, l := range leases {
		if macEqual(l.HardwareAddress, mac) {
			return l, true
		}
	}
	return client.DHCPReservedLease{}, false
}
