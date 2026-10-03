// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &DHCPScopeResource{}
	_ resource.ResourceWithImportState = &DHCPScopeResource{}
)

func NewDHCPScopeResource() resource.Resource {
	return &DHCPScopeResource{}
}

// DHCPScopeResource manages a Technitium DHCP scope.
type DHCPScopeResource struct {
	client *client.Client
}

// DHCPStaticRouteModel maps one static_routes entry.
type DHCPStaticRouteModel struct {
	Destination types.String `tfsdk:"destination"`
	SubnetMask  types.String `tfsdk:"subnet_mask"`
	Router      types.String `tfsdk:"router"`
}

// DHCPVendorInfoModel maps one vendor_info entry.
type DHCPVendorInfoModel struct {
	Identifier  types.String `tfsdk:"identifier"`
	Information types.String `tfsdk:"information"`
}

// DHCPGenericOptionModel maps one generic_options entry.
type DHCPGenericOptionModel struct {
	Code  types.Int64  `tfsdk:"code"`
	Value types.String `tfsdk:"value"`
}

// DHCPExclusionModel maps one exclusions entry.
type DHCPExclusionModel struct {
	StartingAddress types.String `tfsdk:"starting_address"`
	EndingAddress   types.String `tfsdk:"ending_address"`
}

// DHCPReservedLeaseModel maps one reserved_leases entry.
type DHCPReservedLeaseModel struct {
	HostName        types.String `tfsdk:"host_name"`
	HardwareAddress types.String `tfsdk:"hardware_address"`
	Address         types.String `tfsdk:"address"`
	Comments        types.String `tfsdk:"comments"`
}

// DHCPScopeResourceModel describes the resource data model.
type DHCPScopeResourceModel struct {
	ID                                   types.String             `tfsdk:"id"`
	Name                                 types.String             `tfsdk:"name"`
	Enabled                              types.Bool               `tfsdk:"enabled"`
	StartingAddress                      types.String             `tfsdk:"starting_address"`
	EndingAddress                        types.String             `tfsdk:"ending_address"`
	SubnetMask                           types.String             `tfsdk:"subnet_mask"`
	LeaseTimeDays                        types.Int64              `tfsdk:"lease_time_days"`
	LeaseTimeHours                       types.Int64              `tfsdk:"lease_time_hours"`
	LeaseTimeMinutes                     types.Int64              `tfsdk:"lease_time_minutes"`
	OfferDelayTime                       types.Int64              `tfsdk:"offer_delay_time"`
	PingCheckEnabled                     types.Bool               `tfsdk:"ping_check_enabled"`
	PingCheckTimeout                     types.Int64              `tfsdk:"ping_check_timeout"`
	PingCheckRetries                     types.Int64              `tfsdk:"ping_check_retries"`
	DomainName                           types.String             `tfsdk:"domain_name"`
	DomainSearchList                     types.List               `tfsdk:"domain_search_list"`
	DNSUpdates                           types.Bool               `tfsdk:"dns_updates"`
	DNSOverwriteForDynamicLease          types.Bool               `tfsdk:"dns_overwrite_for_dynamic_lease"`
	DNSTTL                               types.Int64              `tfsdk:"dns_ttl"`
	ServerAddress                        types.String             `tfsdk:"server_address"`
	ServerHostName                       types.String             `tfsdk:"server_host_name"`
	BootFileName                         types.String             `tfsdk:"boot_file_name"`
	RouterAddress                        types.String             `tfsdk:"router_address"`
	UseThisDNSServer                     types.Bool               `tfsdk:"use_this_dns_server"`
	DNSServers                           types.List               `tfsdk:"dns_servers"`
	WINSServers                          types.List               `tfsdk:"wins_servers"`
	NTPServers                           types.List               `tfsdk:"ntp_servers"`
	NTPServerDomainNames                 types.List               `tfsdk:"ntp_server_domain_names"`
	StaticRoutes                         []DHCPStaticRouteModel   `tfsdk:"static_routes"`
	VendorInfo                           []DHCPVendorInfoModel    `tfsdk:"vendor_info"`
	CAPWAPAcIPAddresses                  types.List               `tfsdk:"capwap_ac_ip_addresses"`
	TFTPServerAddresses                  types.List               `tfsdk:"tftp_server_addresses"`
	GenericOptions                       []DHCPGenericOptionModel `tfsdk:"generic_options"`
	Exclusions                           []DHCPExclusionModel     `tfsdk:"exclusions"`
	ReservedLeases                       []DHCPReservedLeaseModel `tfsdk:"reserved_leases"`
	AllowOnlyReservedLeases              types.Bool               `tfsdk:"allow_only_reserved_leases"`
	BlockLocallyAdministeredMacAddresses types.Bool               `tfsdk:"block_locally_administered_mac_addresses"`
	IgnoreClientIdentifierOption         types.Bool               `tfsdk:"ignore_client_identifier_option"`
}

func (r *DHCPScopeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_scope"
}

func (r *DHCPScopeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Technitium DHCP scope. The DHCP server allocates leases from the " +
			"scope's address range once the scope is enabled. Note: enabling a scope requires the " +
			"Technitium host to have a network interface with a static IP address inside the scope's subnet. " +
			"Terraform owns the scope's list attributes (dns_servers, exclusions, static_routes, and so on, " +
			"with the exception of reserved_leases): they are sent in full on every apply, so values added " +
			"outside Terraform are not reported as drift and are overwritten — or cleared, when the " +
			"attribute is unset — by the next apply.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Scope identifier (same as scope name).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					scopeIDTracksName{},
				},
			},
			"name": schema.StringAttribute{
				Description: "The name of the DHCP scope. Renaming is supported in place.",
				Required:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the scope is enabled (allocating leases). Default: false. " +
					"Enabling requires a host interface with a static IP inside the scope subnet.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"starting_address": schema.StringAttribute{
				Description: "The starting IP address of the scope range.",
				Required:    true,
			},
			"ending_address": schema.StringAttribute{
				Description: "The ending IP address of the scope range.",
				Required:    true,
			},
			"subnet_mask": schema.StringAttribute{
				Description: "The subnet mask of the network (e.g. 255.255.255.0).",
				Required:    true,
			},
			"lease_time_days": schema.Int64Attribute{
				Description: "Lease time, days component. Default: server default (1).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"lease_time_hours": schema.Int64Attribute{
				Description: "Lease time, hours component.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"lease_time_minutes": schema.Int64Attribute{
				Description: "Lease time, minutes component.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"offer_delay_time": schema.Int64Attribute{
				Description: "Delay in milliseconds before sending DHCPOFFER.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"ping_check_enabled": schema.BoolAttribute{
				Description: "Ping an address before offering it to detect conflicts with statically configured devices.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"ping_check_timeout": schema.Int64Attribute{
				Description: "Ping reply timeout in milliseconds.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"ping_check_retries": schema.Int64Attribute{
				Description: "Maximum number of ping attempts.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"domain_name": schema.StringAttribute{
				Description: "Domain name for this network (option 15). When set, the DHCP server adds forward and reverse DNS entries for allocations.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain_search_list": schema.ListAttribute{
				Description: "Domain names clients use as search suffixes (option 119).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"dns_updates": schema.BoolAttribute{
				Description: "Automatically update forward and reverse DNS entries for clients.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"dns_overwrite_for_dynamic_lease": schema.BoolAttribute{
				Description: "Overwrite existing DNS A records matching the client domain name for dynamic leases.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"dns_ttl": schema.Int64Attribute{
				Description: "TTL for DNS records created by the DHCP server.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"server_address": schema.StringAttribute{
				Description: "Next server (TFTP) address used in bootstrap (siaddr). Defaults to this server's address.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"server_host_name": schema.StringAttribute{
				Description: "Bootstrap TFTP server host name (sname / option 66).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"boot_file_name": schema.StringAttribute{
				Description: "Boot file name on the bootstrap TFTP server (file / option 67).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"router_address": schema.StringAttribute{
				Description: "Default gateway address for clients (option 3).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"use_this_dns_server": schema.BoolAttribute{
				Description: "Advertise this DNS server's address as the DNS server for clients (overrides dns_servers).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"dns_servers": schema.ListAttribute{
				Description: "DNS server addresses for clients (option 6). Ignored when use_this_dns_server is true.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"wins_servers": schema.ListAttribute{
				Description: "NBNS/WINS server addresses for clients (option 44).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"ntp_servers": schema.ListAttribute{
				Description: "NTP server addresses for clients (option 42).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"ntp_server_domain_names": schema.ListAttribute{
				Description: "NTP server domain names the DHCP server resolves and passes to clients as option 42.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"capwap_ac_ip_addresses": schema.ListAttribute{
				Description: "CAPWAP Access Controller addresses (option 138).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"tftp_server_addresses": schema.ListAttribute{
				Description: "TFTP / VoIP configuration server addresses (option 150).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"static_routes": schema.ListNestedAttribute{
				Description: "Classless static routes pushed to clients (option 121).",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"destination": schema.StringAttribute{Description: "Destination network address.", Required: true},
						"subnet_mask": schema.StringAttribute{Description: "Destination subnet mask.", Required: true},
						"router":      schema.StringAttribute{Description: "Gateway address for the route.", Required: true},
					},
				},
			},
			"vendor_info": schema.ListNestedAttribute{
				Description: "Vendor-specific information entries (option 43).",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"identifier":  schema.StringAttribute{Description: "Vendor class identifier (or matching expression).", Required: true},
						"information": schema.StringAttribute{Description: "Vendor-specific information as a (colon-separated) hex string.", Required: true},
					},
				},
			},
			"generic_options": schema.ListNestedAttribute{
				Description: "Raw DHCP options not otherwise supported.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"code":  schema.Int64Attribute{Description: "DHCP option code.", Required: true},
						"value": schema.StringAttribute{Description: "Option value as a (colon-separated) hex string.", Required: true},
					},
				},
			},
			"exclusions": schema.ListNestedAttribute{
				Description: "Address ranges excluded from dynamic allocation.",
				Optional:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"starting_address": schema.StringAttribute{Description: "First excluded address.", Required: true},
						"ending_address":   schema.StringAttribute{Description: "Last excluded address.", Required: true},
					},
				},
			},
			"reserved_leases": schema.ListNestedAttribute{
				Description: "Inline MAC-to-IP reservations. While this attribute has never been declared the scope leaves the " +
					"server-side reservation list alone, so standalone technitium_dhcp_reserved_lease resources can manage it. " +
					"Do not combine the two styles on the same scope — a declared list (even an empty one) overwrites the " +
					"server's list on every scope update, and removing the attribute from config clears the list.",
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host_name":        schema.StringAttribute{Description: "Host name override for the client.", Optional: true},
						"hardware_address": schema.StringAttribute{Description: "Client MAC address (e.g. 00-11-22-33-44-55).", Required: true},
						"address":          schema.StringAttribute{Description: "Reserved IP address.", Required: true},
						"comments":         schema.StringAttribute{Description: "Free-form comments.", Optional: true},
					},
				},
			},
			"allow_only_reserved_leases": schema.BoolAttribute{
				Description: "Stop dynamic allocation and serve only reserved leases.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"block_locally_administered_mac_addresses": schema.BoolAttribute{
				Description: "Refuse dynamic allocation for clients with locally administered MAC addresses (privacy/randomized MACs).",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"ignore_client_identifier_option": schema.BoolAttribute{
				Description: "Always use the client MAC address as the lease identifier instead of option 61.",
				Optional:    true,
				Computed:    true,
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// scopeIDTracksName plans the id as the planned name: the id is the scope
// name, so it is known at plan time and changes only on rename.
type scopeIDTracksName struct{}

func (scopeIDTracksName) Description(context.Context) string {
	return "id tracks the scope name"
}

func (scopeIDTracksName) MarkdownDescription(ctx context.Context) string {
	return scopeIDTracksName{}.Description(ctx)
}

func (scopeIDTracksName) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	var name types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	if resp.Diagnostics.HasError() || name.IsUnknown() || name.IsNull() {
		return
	}
	resp.PlanValue = name
}

func (r *DHCPScopeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DHCPScopeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan DHCPScopeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// scopes/set is create-or-update on the server: creating a scope whose
	// name is already taken would silently overwrite its configuration.
	name := plan.Name.ValueString()
	if _, err := r.client.DHCPScopeGet(ctx, name); err == nil {
		resp.Diagnostics.AddError("DHCP scope already exists",
			fmt.Sprintf("A DHCP scope named %q already exists on the server. "+
				"To manage it with Terraform, import it instead: "+
				"terraform import <resource address> %q", name, name))
		return
	} else if !errors.Is(err, client.ErrDHCPScopeNotFound) {
		resp.Diagnostics.AddError("Error checking for existing DHCP scope", err.Error())
		return
	}

	scope := r.scopeFromModel(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	wantEnabled := plan.Enabled.ValueBool()

	if err := r.client.DHCPScopeSet(ctx, scope, ""); err != nil {
		resp.Diagnostics.AddError("Error creating DHCP scope", err.Error())
		return
	}

	// The scope exists on the server from here on. Persist state before any
	// further call so a later failure surfaces on a resource Terraform
	// tracks, rather than orphaning a live scope that the next apply refuses
	// to adopt.
	r.readBack(ctx, name, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The server may auto-enable a newly created scope (when a matching
	// interface exists); reconcile to the planned state either way.
	if err := r.reconcileEnabled(ctx, name, wantEnabled); err != nil {
		resp.Diagnostics.AddError("Error setting DHCP scope enabled state", err.Error())
		return
	}

	r.readBack(ctx, name, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPScopeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DHCPScopeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	scope, err := r.client.DHCPScopeGet(ctx, state.Name.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrDHCPScopeNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading DHCP scope", err.Error())
		return
	}

	enabled, err := r.scopeEnabled(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error reading DHCP scope status", err.Error())
		return
	}

	r.modelFromScope(ctx, scope, enabled, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *DHCPScopeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state DHCPScopeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API addresses scopes by current name; a differing plan name is a rename.
	scope := r.scopeFromModel(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// Removing the reserved_leases attribute (prior state non-nil, plan nil)
	// must clear the server-side list; plain omission would keep it.
	if plan.ReservedLeases == nil && state.ReservedLeases != nil {
		scope.ReservedLeases = []client.DHCPReservedLease{}
	}
	currentName := state.Name.ValueString()
	newName := ""
	if plan.Name.ValueString() != currentName {
		newName = plan.Name.ValueString()
	}
	scope.Name = currentName

	if err := r.client.DHCPScopeSet(ctx, scope, newName); err != nil {
		resp.Diagnostics.AddError("Error updating DHCP scope", err.Error())
		return
	}

	// The scope now answers to the planned name. Persist it before any
	// further call: if one fails, state must not keep a name the server no
	// longer knows, or the next refresh drops the resource.
	if newName != "" {
		state.Name = plan.Name
		state.ID = plan.Name
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	effectiveName := plan.Name.ValueString()
	if err := r.reconcileEnabled(ctx, effectiveName, plan.Enabled.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Error changing DHCP scope enabled state", err.Error())
		return
	}

	r.readBack(ctx, effectiveName, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPScopeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DHCPScopeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DHCPScopeDelete(ctx, state.Name.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting DHCP scope", err.Error())
	}
}

func (r *DHCPScopeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// reconcileEnabled drives the scope's enabled flag to the desired value,
// regardless of what state the server left it in after a set call.
func (r *DHCPScopeResource) reconcileEnabled(ctx context.Context, name string, want bool) error {
	current, err := r.scopeEnabled(ctx, name)
	if err != nil {
		return err
	}
	if current == want {
		return nil
	}
	if want {
		return r.client.DHCPScopeEnable(ctx, name)
	}
	return r.client.DHCPScopeDisable(ctx, name)
}

// scopeEnabled looks up the enabled flag from the scope list (scopes/get does not return it).
func (r *DHCPScopeResource) scopeEnabled(ctx context.Context, name string) (bool, error) {
	summaries, err := r.client.DHCPScopeList(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range summaries {
		if s.Name == name {
			return s.Enabled, nil
		}
	}
	return false, nil
}

// readBack refreshes the model from the server after a write so computed
// values reflect server-side defaults.
func (r *DHCPScopeResource) readBack(ctx context.Context, name string, model *DHCPScopeResourceModel, diags *diag.Diagnostics) {
	scope, err := r.client.DHCPScopeGet(ctx, name)
	if err != nil {
		diags.AddError("Error reading DHCP scope after write", err.Error())
		return
	}
	enabled, err := r.scopeEnabled(ctx, name)
	if err != nil {
		diags.AddError("Error reading DHCP scope status after write", err.Error())
		return
	}
	r.modelFromScope(ctx, scope, enabled, model)
}

// scopeFromModel converts the Terraform model to the client scope struct.
// Unknown or null scalars map to nil so DHCPScopeSet omits their parameters
// and the server keeps its current values (or applies defaults on create).
func (r *DHCPScopeResource) scopeFromModel(ctx context.Context, m *DHCPScopeResourceModel, diags *diag.Diagnostics) client.DHCPScope {
	scope := client.DHCPScope{
		Name:                                 m.Name.ValueString(),
		StartingAddress:                      m.StartingAddress.ValueString(),
		EndingAddress:                        m.EndingAddress.ValueString(),
		SubnetMask:                           m.SubnetMask.ValueString(),
		LeaseTimeDays:                        intPtrFromModel(m.LeaseTimeDays),
		LeaseTimeHours:                       intPtrFromModel(m.LeaseTimeHours),
		LeaseTimeMinutes:                     intPtrFromModel(m.LeaseTimeMinutes),
		OfferDelayTime:                       intPtrFromModel(m.OfferDelayTime),
		PingCheckEnabled:                     boolPtrFromModel(m.PingCheckEnabled),
		PingCheckTimeout:                     intPtrFromModel(m.PingCheckTimeout),
		PingCheckRetries:                     intPtrFromModel(m.PingCheckRetries),
		DomainName:                           stringPtrFromModel(m.DomainName),
		DNSUpdates:                           boolPtrFromModel(m.DNSUpdates),
		DNSOverwriteForDynamicLease:          boolPtrFromModel(m.DNSOverwriteForDynamicLease),
		DNSTTL:                               intPtrFromModel(m.DNSTTL),
		ServerAddress:                        stringPtrFromModel(m.ServerAddress),
		ServerHostName:                       stringPtrFromModel(m.ServerHostName),
		BootFileName:                         stringPtrFromModel(m.BootFileName),
		RouterAddress:                        stringPtrFromModel(m.RouterAddress),
		UseThisDNSServer:                     boolPtrFromModel(m.UseThisDNSServer),
		AllowOnlyReservedLeases:              boolPtrFromModel(m.AllowOnlyReservedLeases),
		BlockLocallyAdministeredMacAddresses: boolPtrFromModel(m.BlockLocallyAdministeredMacAddresses),
		IgnoreClientIdentifierOption:         boolPtrFromModel(m.IgnoreClientIdentifierOption),
	}

	scope.DomainSearchList = stringListFromModel(ctx, m.DomainSearchList, diags)
	scope.DNSServers = stringListFromModel(ctx, m.DNSServers, diags)
	scope.WINSServers = stringListFromModel(ctx, m.WINSServers, diags)
	scope.NTPServers = stringListFromModel(ctx, m.NTPServers, diags)
	scope.NTPServerDomainNames = stringListFromModel(ctx, m.NTPServerDomainNames, diags)
	scope.CAPWAPAcIPAddresses = stringListFromModel(ctx, m.CAPWAPAcIPAddresses, diags)
	scope.TFTPServerAddresses = stringListFromModel(ctx, m.TFTPServerAddresses, diags)

	for _, route := range m.StaticRoutes {
		scope.StaticRoutes = append(scope.StaticRoutes, client.DHCPStaticRoute{
			Destination: route.Destination.ValueString(),
			SubnetMask:  route.SubnetMask.ValueString(),
			Router:      route.Router.ValueString(),
		})
	}
	for _, vi := range m.VendorInfo {
		scope.VendorInfo = append(scope.VendorInfo, client.DHCPVendorInfo{
			Identifier:  vi.Identifier.ValueString(),
			Information: vi.Information.ValueString(),
		})
	}
	for _, opt := range m.GenericOptions {
		scope.GenericOptions = append(scope.GenericOptions, client.DHCPGenericOption{
			Code:  int(opt.Code.ValueInt64()),
			Value: opt.Value.ValueString(),
		})
	}
	for _, excl := range m.Exclusions {
		scope.Exclusions = append(scope.Exclusions, client.DHCPExclusion{
			StartingAddress: excl.StartingAddress.ValueString(),
			EndingAddress:   excl.EndingAddress.ValueString(),
		})
	}
	// nil when the attribute is absent from config, non-nil (possibly empty)
	// when declared: DHCPScopeSet omits the reservedLeases parameter for nil
	// so scope updates don't wipe standalone technitium_dhcp_reserved_lease
	// reservations, while a declared list still overwrites the server's.
	if m.ReservedLeases != nil {
		scope.ReservedLeases = make([]client.DHCPReservedLease, 0, len(m.ReservedLeases))
		for _, lease := range m.ReservedLeases {
			scope.ReservedLeases = append(scope.ReservedLeases, client.DHCPReservedLease{
				HostName:        lease.HostName.ValueString(),
				HardwareAddress: lease.HardwareAddress.ValueString(),
				Address:         lease.Address.ValueString(),
				Comments:        lease.Comments.ValueString(),
			})
		}
	}

	return scope
}

// modelFromScope refreshes the Terraform model from the server scope. Optional
// (non-computed) list attributes keep null when unset and the server reports
// empty, mirroring readStringList semantics.
func (r *DHCPScopeResource) modelFromScope(ctx context.Context, scope *client.DHCPScope, enabled bool, m *DHCPScopeResourceModel) {
	m.ID = types.StringValue(scope.Name)
	m.Name = types.StringValue(scope.Name)
	m.Enabled = types.BoolValue(enabled)
	m.StartingAddress = types.StringValue(scope.StartingAddress)
	m.EndingAddress = types.StringValue(scope.EndingAddress)
	m.SubnetMask = types.StringValue(scope.SubnetMask)
	m.LeaseTimeDays = types.Int64Value(int64(deref(scope.LeaseTimeDays)))
	m.LeaseTimeHours = types.Int64Value(int64(deref(scope.LeaseTimeHours)))
	m.LeaseTimeMinutes = types.Int64Value(int64(deref(scope.LeaseTimeMinutes)))
	m.OfferDelayTime = types.Int64Value(int64(deref(scope.OfferDelayTime)))
	m.PingCheckEnabled = types.BoolValue(deref(scope.PingCheckEnabled))
	m.PingCheckTimeout = types.Int64Value(int64(deref(scope.PingCheckTimeout)))
	m.PingCheckRetries = types.Int64Value(int64(deref(scope.PingCheckRetries)))
	m.DomainName = types.StringValue(deref(scope.DomainName))
	m.DNSUpdates = types.BoolValue(deref(scope.DNSUpdates))
	m.DNSOverwriteForDynamicLease = types.BoolValue(deref(scope.DNSOverwriteForDynamicLease))
	m.DNSTTL = types.Int64Value(int64(deref(scope.DNSTTL)))
	m.ServerAddress = types.StringValue(deref(scope.ServerAddress))
	m.ServerHostName = types.StringValue(deref(scope.ServerHostName))
	m.BootFileName = types.StringValue(deref(scope.BootFileName))
	m.RouterAddress = types.StringValue(deref(scope.RouterAddress))
	m.UseThisDNSServer = types.BoolValue(deref(scope.UseThisDNSServer))
	m.AllowOnlyReservedLeases = types.BoolValue(deref(scope.AllowOnlyReservedLeases))
	m.BlockLocallyAdministeredMacAddresses = types.BoolValue(deref(scope.BlockLocallyAdministeredMacAddresses))
	m.IgnoreClientIdentifierOption = types.BoolValue(deref(scope.IgnoreClientIdentifierOption))

	readStringList(ctx, &m.DomainSearchList, scope.DomainSearchList)
	readStringList(ctx, &m.DNSServers, scope.DNSServers)
	readStringList(ctx, &m.WINSServers, scope.WINSServers)
	readStringList(ctx, &m.NTPServers, scope.NTPServers)
	readStringList(ctx, &m.NTPServerDomainNames, scope.NTPServerDomainNames)
	readStringList(ctx, &m.CAPWAPAcIPAddresses, scope.CAPWAPAcIPAddresses)
	readStringList(ctx, &m.TFTPServerAddresses, scope.TFTPServerAddresses)

	// Nested object lists: keep null (nil slice) when unset in config,
	// mirroring readStringList semantics. This also keeps the scope from
	// claiming reservations owned by technitium_dhcp_reserved_lease resources.
	if m.StaticRoutes != nil {
		routes := make([]DHCPStaticRouteModel, 0, len(scope.StaticRoutes))
		for _, route := range scope.StaticRoutes {
			routes = append(routes, DHCPStaticRouteModel{
				Destination: types.StringValue(route.Destination),
				SubnetMask:  types.StringValue(route.SubnetMask),
				Router:      types.StringValue(route.Router),
			})
		}
		m.StaticRoutes = routes
	}
	if m.VendorInfo != nil {
		prior := m.VendorInfo
		entries := make([]DHCPVendorInfoModel, 0, len(scope.VendorInfo))
		for i, vi := range scope.VendorInfo {
			entry := DHCPVendorInfoModel{
				Identifier:  types.StringValue(vi.Identifier),
				Information: types.StringValue(vi.Information),
			}
			// Keep the configured hex formatting when it encodes the same
			// bytes as the server's normalized form.
			if i < len(prior) && hexValueEqual(prior[i].Information.ValueString(), vi.Information) {
				entry.Information = prior[i].Information
			}
			entries = append(entries, entry)
		}
		m.VendorInfo = entries
	}
	if m.GenericOptions != nil {
		prior := m.GenericOptions
		opts := make([]DHCPGenericOptionModel, 0, len(scope.GenericOptions))
		for i, opt := range scope.GenericOptions {
			model := DHCPGenericOptionModel{
				Code:  types.Int64Value(int64(opt.Code)),
				Value: types.StringValue(opt.Value),
			}
			if i < len(prior) && prior[i].Code.ValueInt64() == int64(opt.Code) &&
				hexValueEqual(prior[i].Value.ValueString(), opt.Value) {
				model.Value = prior[i].Value
			}
			opts = append(opts, model)
		}
		m.GenericOptions = opts
	}
	if m.Exclusions != nil {
		exclusions := make([]DHCPExclusionModel, 0, len(scope.Exclusions))
		for _, excl := range scope.Exclusions {
			exclusions = append(exclusions, DHCPExclusionModel{
				StartingAddress: types.StringValue(excl.StartingAddress),
				EndingAddress:   types.StringValue(excl.EndingAddress),
			})
		}
		m.Exclusions = exclusions
	}
	if m.ReservedLeases != nil {
		prior := m.ReservedLeases
		leases := make([]DHCPReservedLeaseModel, 0, len(scope.ReservedLeases))
		for _, lease := range scope.ReservedLeases {
			model := DHCPReservedLeaseModel{
				HostName:        stringOrNull(lease.HostName),
				HardwareAddress: types.StringValue(lease.HardwareAddress),
				Address:         types.StringValue(lease.Address),
				Comments:        stringOrNull(lease.Comments),
			}
			// Keep the configured MAC formatting; the server normalizes
			// case and separators.
			for _, p := range prior {
				if macEqual(p.HardwareAddress.ValueString(), lease.HardwareAddress) {
					model.HardwareAddress = p.HardwareAddress
					break
				}
			}
			leases = append(leases, model)
		}
		m.ReservedLeases = leases
	}
}

// stringListFromModel converts a types.List of strings to []string (nil when null/unknown).
func stringListFromModel(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(list.ElementsAs(ctx, &out, false)...)
	return out
}

// stringOrNull maps an empty string from the API to a null value.
func stringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// intPtrFromModel maps a known types.Int64 to *int, and null/unknown to nil.
func intPtrFromModel(v types.Int64) *int {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	i := int(v.ValueInt64())
	return &i
}

// boolPtrFromModel maps a known types.Bool to *bool, and null/unknown to nil.
func boolPtrFromModel(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

// stringPtrFromModel maps a known types.String to *string, and null/unknown to nil.
func stringPtrFromModel(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

// hexValueEqual compares hex option values ignoring case and :/- separator
// differences (e.g. "0a:2b" and "0A-2B" encode the same bytes).
func hexValueEqual(a, b string) bool {
	return normalizeHexValue(a) == normalizeHexValue(b)
}

func normalizeHexValue(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	return s
}

// deref returns the pointed-to value, or the zero value for nil.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
