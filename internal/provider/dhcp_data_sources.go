// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// technitium_dhcp_scope (single scope, full configuration)
// ---------------------------------------------------------------------------

var _ datasource.DataSource = &DHCPScopeDataSource{}

func NewDHCPScopeDataSource() datasource.DataSource {
	return &DHCPScopeDataSource{}
}

// DHCPScopeDataSource reads a single DHCP scope's full configuration.
type DHCPScopeDataSource struct {
	client *client.Client
}

// DHCPScopeDataSourceModel mirrors the scope configuration (all computed).
type DHCPScopeDataSourceModel struct {
	Name                    types.String             `tfsdk:"name"`
	Enabled                 types.Bool               `tfsdk:"enabled"`
	StartingAddress         types.String             `tfsdk:"starting_address"`
	EndingAddress           types.String             `tfsdk:"ending_address"`
	SubnetMask              types.String             `tfsdk:"subnet_mask"`
	LeaseTimeDays           types.Int64              `tfsdk:"lease_time_days"`
	LeaseTimeHours          types.Int64              `tfsdk:"lease_time_hours"`
	LeaseTimeMinutes        types.Int64              `tfsdk:"lease_time_minutes"`
	DomainName              types.String             `tfsdk:"domain_name"`
	RouterAddress           types.String             `tfsdk:"router_address"`
	UseThisDNSServer        types.Bool               `tfsdk:"use_this_dns_server"`
	DNSServers              types.List               `tfsdk:"dns_servers"`
	NTPServers              types.List               `tfsdk:"ntp_servers"`
	Exclusions              []DHCPExclusionModel     `tfsdk:"exclusions"`
	ReservedLeases          []DHCPReservedLeaseModel `tfsdk:"reserved_leases"`
	AllowOnlyReservedLeases types.Bool               `tfsdk:"allow_only_reserved_leases"`
}

func (d *DHCPScopeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_scope"
}

func (d *DHCPScopeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a Technitium DHCP scope configuration.",
		Attributes: map[string]schema.Attribute{
			"name":               schema.StringAttribute{Description: "Name of the DHCP scope.", Required: true},
			"enabled":            schema.BoolAttribute{Description: "Whether the scope is enabled.", Computed: true},
			"starting_address":   schema.StringAttribute{Description: "Starting IP address of the range.", Computed: true},
			"ending_address":     schema.StringAttribute{Description: "Ending IP address of the range.", Computed: true},
			"subnet_mask":        schema.StringAttribute{Description: "Subnet mask.", Computed: true},
			"lease_time_days":    schema.Int64Attribute{Description: "Lease time, days component.", Computed: true},
			"lease_time_hours":   schema.Int64Attribute{Description: "Lease time, hours component.", Computed: true},
			"lease_time_minutes": schema.Int64Attribute{Description: "Lease time, minutes component.", Computed: true},
			"domain_name":        schema.StringAttribute{Description: "Domain name (option 15).", Computed: true},
			"router_address":     schema.StringAttribute{Description: "Default gateway (option 3).", Computed: true},
			"use_this_dns_server": schema.BoolAttribute{
				Description: "Whether clients are pointed at this DNS server.", Computed: true,
			},
			"dns_servers": schema.ListAttribute{Description: "DNS servers (option 6).", Computed: true, ElementType: types.StringType},
			"ntp_servers": schema.ListAttribute{Description: "NTP servers (option 42).", Computed: true, ElementType: types.StringType},
			"exclusions": schema.ListNestedAttribute{
				Description: "Excluded address ranges.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"starting_address": schema.StringAttribute{Computed: true},
						"ending_address":   schema.StringAttribute{Computed: true},
					},
				},
			},
			"reserved_leases": schema.ListNestedAttribute{
				Description: "MAC-to-IP reservations.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host_name":        schema.StringAttribute{Computed: true},
						"hardware_address": schema.StringAttribute{Computed: true},
						"address":          schema.StringAttribute{Computed: true},
						"comments":         schema.StringAttribute{Computed: true},
					},
				},
			},
			"allow_only_reserved_leases": schema.BoolAttribute{Description: "Whether only reserved leases are served.", Computed: true},
		},
	}
}

func (d *DHCPScopeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	d.client = providerData.Client
}

func (d *DHCPScopeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config DHCPScopeDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := config.Name.ValueString()
	scope, err := d.client.DHCPScopeGet(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Error reading DHCP scope", err.Error())
		return
	}

	enabled := false
	if summaries, err := d.client.DHCPScopeList(ctx); err == nil {
		for _, s := range summaries {
			if s.Name == name {
				enabled = s.Enabled
				break
			}
		}
	} else {
		resp.Diagnostics.AddError("Error reading DHCP scope status", err.Error())
		return
	}

	config.Enabled = types.BoolValue(enabled)
	config.StartingAddress = types.StringValue(scope.StartingAddress)
	config.EndingAddress = types.StringValue(scope.EndingAddress)
	config.SubnetMask = types.StringValue(scope.SubnetMask)
	config.LeaseTimeDays = types.Int64Value(int64(deref(scope.LeaseTimeDays)))
	config.LeaseTimeHours = types.Int64Value(int64(deref(scope.LeaseTimeHours)))
	config.LeaseTimeMinutes = types.Int64Value(int64(deref(scope.LeaseTimeMinutes)))
	config.DomainName = types.StringValue(deref(scope.DomainName))
	config.RouterAddress = types.StringValue(deref(scope.RouterAddress))
	config.UseThisDNSServer = types.BoolValue(deref(scope.UseThisDNSServer))
	config.AllowOnlyReservedLeases = types.BoolValue(deref(scope.AllowOnlyReservedLeases))

	dnsServers, _ := types.ListValueFrom(ctx, types.StringType, emptyIfNil(scope.DNSServers))
	config.DNSServers = dnsServers
	ntpServers, _ := types.ListValueFrom(ctx, types.StringType, emptyIfNil(scope.NTPServers))
	config.NTPServers = ntpServers

	config.Exclusions = make([]DHCPExclusionModel, 0, len(scope.Exclusions))
	for _, excl := range scope.Exclusions {
		config.Exclusions = append(config.Exclusions, DHCPExclusionModel{
			StartingAddress: types.StringValue(excl.StartingAddress),
			EndingAddress:   types.StringValue(excl.EndingAddress),
		})
	}
	config.ReservedLeases = make([]DHCPReservedLeaseModel, 0, len(scope.ReservedLeases))
	for _, lease := range scope.ReservedLeases {
		config.ReservedLeases = append(config.ReservedLeases, DHCPReservedLeaseModel{
			HostName:        stringOrNull(lease.HostName),
			HardwareAddress: types.StringValue(lease.HardwareAddress),
			Address:         types.StringValue(lease.Address),
			Comments:        stringOrNull(lease.Comments),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// ---------------------------------------------------------------------------
// technitium_dhcp_scopes (all scope summaries)
// ---------------------------------------------------------------------------

var _ datasource.DataSource = &DHCPScopesDataSource{}

func NewDHCPScopesDataSource() datasource.DataSource {
	return &DHCPScopesDataSource{}
}

// DHCPScopesDataSource lists all DHCP scopes on the server.
type DHCPScopesDataSource struct {
	client *client.Client
}

// DHCPScopeSummaryModel maps one scopes entry.
type DHCPScopeSummaryModel struct {
	Name             types.String `tfsdk:"name"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	StartingAddress  types.String `tfsdk:"starting_address"`
	EndingAddress    types.String `tfsdk:"ending_address"`
	SubnetMask       types.String `tfsdk:"subnet_mask"`
	NetworkAddress   types.String `tfsdk:"network_address"`
	BroadcastAddress types.String `tfsdk:"broadcast_address"`
}

// DHCPScopesDataSourceModel is the technitium_dhcp_scopes model.
type DHCPScopesDataSourceModel struct {
	Scopes []DHCPScopeSummaryModel `tfsdk:"scopes"`
}

func (d *DHCPScopesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_scopes"
}

func (d *DHCPScopesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all DHCP scopes configured on the server.",
		Attributes: map[string]schema.Attribute{
			"scopes": schema.ListNestedAttribute{
				Description: "All DHCP scopes.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name":              schema.StringAttribute{Computed: true},
						"enabled":           schema.BoolAttribute{Computed: true},
						"starting_address":  schema.StringAttribute{Computed: true},
						"ending_address":    schema.StringAttribute{Computed: true},
						"subnet_mask":       schema.StringAttribute{Computed: true},
						"network_address":   schema.StringAttribute{Computed: true},
						"broadcast_address": schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *DHCPScopesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	d.client = providerData.Client
}

func (d *DHCPScopesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	summaries, err := d.client.DHCPScopeList(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing DHCP scopes", err.Error())
		return
	}

	var state DHCPScopesDataSourceModel
	state.Scopes = make([]DHCPScopeSummaryModel, 0, len(summaries))
	for _, s := range summaries {
		state.Scopes = append(state.Scopes, DHCPScopeSummaryModel{
			Name:             types.StringValue(s.Name),
			Enabled:          types.BoolValue(s.Enabled),
			StartingAddress:  types.StringValue(s.StartingAddress),
			EndingAddress:    types.StringValue(s.EndingAddress),
			SubnetMask:       types.StringValue(s.SubnetMask),
			NetworkAddress:   types.StringValue(s.NetworkAddress),
			BroadcastAddress: types.StringValue(s.BroadcastAddress),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// ---------------------------------------------------------------------------
// technitium_dhcp_leases (runtime lease table)
// ---------------------------------------------------------------------------

var _ datasource.DataSource = &DHCPLeasesDataSource{}

func NewDHCPLeasesDataSource() datasource.DataSource {
	return &DHCPLeasesDataSource{}
}

// DHCPLeasesDataSource lists current DHCP leases, optionally filtered by scope.
type DHCPLeasesDataSource struct {
	client *client.Client
}

// DHCPLeaseModel maps one lease entry.
type DHCPLeaseModel struct {
	Scope            types.String `tfsdk:"scope"`
	Type             types.String `tfsdk:"type"`
	HardwareAddress  types.String `tfsdk:"hardware_address"`
	ClientIdentifier types.String `tfsdk:"client_identifier"`
	Address          types.String `tfsdk:"address"`
	HostName         types.String `tfsdk:"host_name"`
	LeaseObtained    types.String `tfsdk:"lease_obtained"`
	LeaseExpires     types.String `tfsdk:"lease_expires"`
}

// DHCPLeasesDataSourceModel is the technitium_dhcp_leases model.
type DHCPLeasesDataSourceModel struct {
	Scope  types.String     `tfsdk:"scope"`
	Leases []DHCPLeaseModel `tfsdk:"leases"`
}

func (d *DHCPLeasesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_leases"
}

func (d *DHCPLeasesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists current DHCP leases (dynamic and reserved), optionally filtered by scope. " +
			"Returns an empty list when no leases match.",
		Attributes: map[string]schema.Attribute{
			"scope": schema.StringAttribute{
				Description: "Only return leases belonging to this scope.",
				Optional:    true,
			},
			"leases": schema.ListNestedAttribute{
				Description: "Current leases.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"scope":             schema.StringAttribute{Computed: true},
						"type":              schema.StringAttribute{Description: "Dynamic or Reserved.", Computed: true},
						"hardware_address":  schema.StringAttribute{Computed: true},
						"client_identifier": schema.StringAttribute{Computed: true},
						"address":           schema.StringAttribute{Computed: true},
						"host_name":         schema.StringAttribute{Computed: true},
						"lease_obtained":    schema.StringAttribute{Computed: true},
						"lease_expires":     schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *DHCPLeasesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	d.client = providerData.Client
}

func (d *DHCPLeasesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config DHCPLeasesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	leases, err := d.client.DHCPLeaseList(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing DHCP leases", err.Error())
		return
	}

	scopeFilter := config.Scope.ValueString()
	config.Leases = make([]DHCPLeaseModel, 0, len(leases))
	for i := range leases {
		lease := &leases[i]
		if scopeFilter != "" && lease.Scope != scopeFilter {
			continue
		}
		config.Leases = append(config.Leases, DHCPLeaseModel{
			Scope:            types.StringValue(lease.Scope),
			Type:             types.StringValue(lease.Type),
			HardwareAddress:  types.StringValue(lease.HardwareAddress),
			ClientIdentifier: types.StringValue(lease.ClientIdentifier),
			Address:          types.StringValue(lease.Address),
			HostName:         stringOrNull(lease.HostName),
			LeaseObtained:    types.StringValue(lease.LeaseObtained),
			LeaseExpires:     types.StringValue(lease.LeaseExpires),
		})
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// emptyIfNil maps a nil slice to an empty one for computed-only list attributes.
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
