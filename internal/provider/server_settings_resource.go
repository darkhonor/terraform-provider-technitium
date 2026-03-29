// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                     = &ServerSettingsResource{}
	_ resource.ResourceWithImportState      = &ServerSettingsResource{}
	_ resource.ResourceWithModifyPlan       = &ServerSettingsResource{}
	_ resource.ResourceWithConfigValidators = &ServerSettingsResource{}
)

func NewServerSettingsResource() resource.Resource {
	return &ServerSettingsResource{}
}

type ServerSettingsResource struct {
	client       *client.Client
	providerData *TechnitiumProviderData
}

type ServerSettingsResourceModel struct {
	ID                          types.String `tfsdk:"id"`
	DnssecValidation            types.Bool   `tfsdk:"dnssec_validation"`
	Recursion                   types.String `tfsdk:"recursion"`
	RecursionNetworkACL         types.List   `tfsdk:"recursion_network_acl"`
	QnameMinimization           types.Bool   `tfsdk:"qname_minimization"`
	RandomizeName               types.Bool   `tfsdk:"randomize_name"`
	LogQueries                  types.Bool   `tfsdk:"log_queries"`
	LoggingType                 types.String `tfsdk:"logging_type"`
	MaxLogFileDays              types.Int64  `tfsdk:"max_log_file_days"`
	EnableBlocking              types.Bool   `tfsdk:"enable_blocking"`
	AllowTxtBlockingReport       types.Bool   `tfsdk:"allow_txt_blocking_report"`
	BlockingBypassList           types.List   `tfsdk:"blocking_bypass_list"`
	BlockingType                 types.String `tfsdk:"blocking_type"`
	BlockingAnswerTTL            types.Int64  `tfsdk:"blocking_answer_ttl"`
	CustomBlockingAddresses      types.List   `tfsdk:"custom_blocking_addresses"`
	BlockListUrls                types.List   `tfsdk:"block_list_urls"`
	BlockListUpdateIntervalHours types.Int64  `tfsdk:"block_list_update_interval_hours"`
	ServeStale                  types.Bool   `tfsdk:"serve_stale"`
	Forwarders                  types.List   `tfsdk:"forwarders"`
	ForwarderProtocol           types.String `tfsdk:"forwarder_protocol"`
	EnableDnsOverTls            types.Bool   `tfsdk:"enable_dns_over_tls"`
	EnableDnsOverHttps          types.Bool   `tfsdk:"enable_dns_over_https"`
	ZoneTransferAllowedNetworks types.List   `tfsdk:"zone_transfer_allowed_networks"`
	NotifyAllowedNetworks       types.List   `tfsdk:"notify_allowed_networks"`
	UdpPayloadSize              types.Int64  `tfsdk:"udp_payload_size"`
	CacheMinimumRecordTtl       types.Int64  `tfsdk:"cache_minimum_record_ttl"`
	CacheMaximumRecordTtl       types.Int64  `tfsdk:"cache_maximum_record_ttl"`
	// Computed
	Version types.String `tfsdk:"version"`
	Uptime  types.String `tfsdk:"uptime"`
}

func (r *ServerSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_server_settings"
}

func (r *ServerSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Technitium DNS Server settings. Singleton resource — one per provider instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Fixed identifier: server-settings.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"dnssec_validation": schema.BoolAttribute{
				Description: "Enable DNSSEC validation. STIG BIND-9X-001650 (SC-21).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"recursion": schema.StringAttribute{
				Description: "Recursion policy. STIG BIND-9X-001380 (SC-5). Valid: Allow, Deny, AllowOnlyForPrivateNetworks, UseSpecifiedNetworkACL.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("AllowOnlyForPrivateNetworks"),
			},
			"recursion_network_acl": schema.ListAttribute{
				Description: "Network ACL for recursion when using UseSpecifiedNetworkACL. STIG BIND-9X-001740 (SC-5).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"qname_minimization": schema.BoolAttribute{
				Description: "Enable QNAME minimization. STIG BIND-9X-002440 (CM-6).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"randomize_name": schema.BoolAttribute{
				Description: "Randomize query name case (0x20 encoding). STIG BIND-9X-001490 (CM-6).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"log_queries": schema.BoolAttribute{
				Description: "Enable query logging. STIG BIND-9X-001110 (AU-12).",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"logging_type": schema.StringAttribute{
				Description: "Logging output type. STIG BIND-9X-001900 (AU-4). Valid: None, File, Console, FileAndConsole.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("FileAndConsole"),
			},
			"max_log_file_days": schema.Int64Attribute{
				Description: "Maximum days to retain log files. STIG BIND-9X-001890 (AU-4).",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(365),
			},
			"enable_blocking": schema.BoolAttribute{
				Description: "Enable DNS blocking.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"allow_txt_blocking_report": schema.BoolAttribute{
				Description: "Allow TXT record blocking report queries.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"blocking_bypass_list": schema.ListAttribute{
				Description: "List of domains/networks that bypass blocking.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"blocking_type": schema.StringAttribute{
				Description: "Blocking response type. Valid: NxDomain, AnyAddress, TxtRecord, CustomAddress.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(client.BlockingTypeNxDomain),
				Validators: []validator.String{
					stringvalidator.OneOf(client.ValidBlockingTypes...),
				},
			},
			"blocking_answer_ttl": schema.Int64Attribute{
				Description: "TTL in seconds for blocking responses.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(30),
			},
			"custom_blocking_addresses": schema.ListAttribute{
				Description: "Custom IP addresses returned for blocked queries (used with CustomAddress blocking type).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"block_list_urls": schema.ListAttribute{
				Description: "URLs of block list feeds to subscribe to.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"block_list_update_interval_hours": schema.Int64Attribute{
				Description: "Hours between block list update checks.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(24),
			},
			"serve_stale": schema.BoolAttribute{
				Description: "Serve stale records when upstream is unavailable.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"forwarders": schema.ListAttribute{
				Description: "List of forwarder addresses. STIG BIND-9X-001360 (SC-20).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"forwarder_protocol": schema.StringAttribute{
				Description: "Forwarder transport protocol. STIG SC-8. Valid: Udp, Tcp, Tls, Https, Quic.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("Tls"),
			},
			"enable_dns_over_tls": schema.BoolAttribute{
				Description: "Enable DNS-over-TLS listener. STIG SC-8.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"enable_dns_over_https": schema.BoolAttribute{
				Description: "Enable DNS-over-HTTPS listener. STIG SC-8.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"zone_transfer_allowed_networks": schema.ListAttribute{
				Description: "Networks allowed to perform zone transfers. STIG BIND-9X-001010 (AC-10).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"notify_allowed_networks": schema.ListAttribute{
				Description: "Networks allowed to send notify. STIG BIND-9X-001390 (SC-20).",
				Optional:    true,
				ElementType: types.StringType,
			},
			"udp_payload_size": schema.Int64Attribute{
				Description: "EDNS UDP payload size in bytes.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(1232),
			},
			"cache_minimum_record_ttl": schema.Int64Attribute{
				Description: "Minimum TTL for cached records in seconds.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(10),
			},
			"cache_maximum_record_ttl": schema.Int64Attribute{
				Description: "Maximum TTL for cached records in seconds.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(604800),
			},
			// Computed
			"version": schema.StringAttribute{
				Description: "Technitium DNS Server version.",
				Computed:    true,
			},
			"uptime": schema.StringAttribute{
				Description: "Server uptime timestamp.",
				Computed:    true,
			},
		},
	}
}

func (r *ServerSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	r.providerData = providerData
	r.client = providerData.Client
}

func (r *ServerSettingsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy plan
	}
	if r.providerData != nil && r.providerData.STIGEngine != nil {
		r.providerData.STIGEngine.ValidatePlan(
			ctx,
			validators.ResourceServerSettings,
			&validators.TFPlanAdapter{Plan: req.Plan},
			&validators.TFStateAdapter{State: req.State},
			&resp.Diagnostics,
		)
	}
}

func (r *ServerSettingsResource) ConfigValidators(ctx context.Context) []resource.ConfigValidator {
	if r.providerData == nil || r.providerData.STIGEngine == nil {
		return nil
	}
	return []resource.ConfigValidator{
		newSTIGConfigValidator(r.providerData.STIGEngine, validators.ResourceServerSettings),
	}
}

func (r *ServerSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ServerSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue("server-settings")

	// Apply settings
	params := r.buildParams(ctx, &plan)
	if len(params) > 0 {
		if err := r.client.SettingsSet(ctx, params); err != nil {
			resp.Diagnostics.AddError("Error setting server settings", err.Error())
			return
		}
	}

	// Read back
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading server settings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ServerSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ServerSettingsResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readState(ctx, &state); err != nil {
		resp.Diagnostics.AddError("Error reading server settings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ServerSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ServerSettingsResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := r.buildParams(ctx, &plan)
	if len(params) > 0 {
		if err := r.client.SettingsSet(ctx, params); err != nil {
			resp.Diagnostics.AddError("Error updating server settings", err.Error())
			return
		}
	}

	plan.ID = types.StringValue("server-settings")
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading server settings", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ServerSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Server settings can't be deleted — they always exist.
	// On destroy, we just remove from state. The server keeps its current settings.
}

func (r *ServerSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// buildParams converts the model to API parameters.
func (r *ServerSettingsResource) buildParams(ctx context.Context, model *ServerSettingsResourceModel) map[string]string {
	params := map[string]string{}

	setBool(params, "dnssecValidation", model.DnssecValidation)
	setString(params, "recursion", model.Recursion)
	setStringList(ctx, params, "recursionNetworkACL", model.RecursionNetworkACL)
	setBool(params, "qnameMinimization", model.QnameMinimization)
	setBool(params, "randomizeName", model.RandomizeName)
	setBool(params, "logQueries", model.LogQueries)
	setString(params, "loggingType", model.LoggingType)
	setInt(params, "maxLogFileDays", model.MaxLogFileDays)
	setBool(params, "enableBlocking", model.EnableBlocking)
	setBool(params, "allowTxtBlockingReport", model.AllowTxtBlockingReport)
	setStringList(ctx, params, "blockingBypassList", model.BlockingBypassList)
	setString(params, "blockingType", model.BlockingType)
	setInt(params, "blockingAnswerTtl", model.BlockingAnswerTTL)
	setStringList(ctx, params, "customBlockingAddresses", model.CustomBlockingAddresses)
	setStringList(ctx, params, "blockListUrls", model.BlockListUrls)
	setInt(params, "blockListUpdateIntervalHours", model.BlockListUpdateIntervalHours)
	setBool(params, "serveStale", model.ServeStale)
	setStringList(ctx, params, "forwarders", model.Forwarders)
	setString(params, "forwarderProtocol", model.ForwarderProtocol)
	setBool(params, "enableDnsOverTls", model.EnableDnsOverTls)
	setBool(params, "enableDnsOverHttps", model.EnableDnsOverHttps)
	setStringList(ctx, params, "zoneTransferAllowedNetworks", model.ZoneTransferAllowedNetworks)
	setStringList(ctx, params, "notifyAllowedNetworks", model.NotifyAllowedNetworks)
	setInt(params, "udpPayloadSize", model.UdpPayloadSize)
	setInt(params, "cacheMinimumRecordTtl", model.CacheMinimumRecordTtl)
	setInt(params, "cacheMaximumRecordTtl", model.CacheMaximumRecordTtl)

	return params
}

// readState reads current settings from the API into the model.
func (r *ServerSettingsResource) readState(ctx context.Context, model *ServerSettingsResourceModel) error {
	settings, err := r.client.SettingsGet(ctx)
	if err != nil {
		return err
	}

	model.ID = types.StringValue("server-settings")
	model.Version = types.StringValue(settings.Version)
	model.Uptime = types.StringValue(settings.Uptimestamp)
	model.DnssecValidation = types.BoolValue(settings.DnssecValidation)
	model.Recursion = types.StringValue(settings.Recursion)
	model.QnameMinimization = types.BoolValue(settings.QnameMinimization)
	model.RandomizeName = types.BoolValue(settings.RandomizeName)
	model.LogQueries = types.BoolValue(settings.LogQueries)
	model.LoggingType = types.StringValue(settings.LoggingType)
	model.MaxLogFileDays = types.Int64Value(int64(settings.MaxLogFileDays))
	model.EnableBlocking = types.BoolValue(settings.EnableBlocking)
	model.AllowTxtBlockingReport = types.BoolValue(settings.AllowTxtBlockingReport)
	model.BlockingType = types.StringValue(settings.BlockingType)
	model.BlockingAnswerTTL = types.Int64Value(int64(settings.BlockingAnswerTTL))
	model.BlockListUpdateIntervalHours = types.Int64Value(int64(settings.BlockListUpdateIntervalHours))
	model.ServeStale = types.BoolValue(settings.ServeStale)
	// ForwarderProtocol: the API only persists this when forwarders are configured.
	// If no forwarders, keep the planned value to avoid drift.
	if len(settings.Forwarders) > 0 || model.ForwarderProtocol.IsNull() || model.ForwarderProtocol.IsUnknown() {
		model.ForwarderProtocol = types.StringValue(settings.ForwarderProtocol)
	}
	model.EnableDnsOverTls = types.BoolValue(settings.EnableDnsOverTls)
	model.EnableDnsOverHttps = types.BoolValue(settings.EnableDnsOverHttps)
	model.UdpPayloadSize = types.Int64Value(int64(settings.UdpPayloadSize))
	model.CacheMinimumRecordTtl = types.Int64Value(int64(settings.CacheMinimumRecordTtl))
	model.CacheMaximumRecordTtl = types.Int64Value(int64(settings.CacheMaximumRecordTtl))

	// Lists
	readStringList(ctx, &model.RecursionNetworkACL, settings.RecursionNetworkACL)
	readStringList(ctx, &model.BlockingBypassList, settings.BlockingBypassList)
	readStringList(ctx, &model.CustomBlockingAddresses, settings.CustomBlockingAddresses)
	readStringList(ctx, &model.BlockListUrls, settings.BlockListUrls)
	readStringList(ctx, &model.Forwarders, settings.Forwarders)
	readStringList(ctx, &model.ZoneTransferAllowedNetworks, settings.ZoneTransferAllowedNetworks)
	readStringList(ctx, &model.NotifyAllowedNetworks, settings.NotifyAllowedNetworks)

	return nil
}

// Helper functions for building params
func setBool(params map[string]string, key string, val types.Bool) {
	if !val.IsNull() && !val.IsUnknown() {
		if val.ValueBool() {
			params[key] = "true"
		} else {
			params[key] = "false"
		}
	}
}

func setString(params map[string]string, key string, val types.String) {
	if !val.IsNull() && !val.IsUnknown() {
		params[key] = val.ValueString()
	}
}

func setInt(params map[string]string, key string, val types.Int64) {
	if !val.IsNull() && !val.IsUnknown() {
		params[key] = fmt.Sprintf("%d", val.ValueInt64())
	}
}

func setStringList(ctx context.Context, params map[string]string, key string, val types.List) {
	if !val.IsNull() && !val.IsUnknown() {
		var items []string
		val.ElementsAs(ctx, &items, false)
		if len(items) > 0 {
			params[key] = strings.Join(items, ",")
		} else {
			params[key] = "false" // Technitium uses "false" to clear a list
		}
	}
}

func readStringList(ctx context.Context, target *types.List, source []string) {
	// If the plan had null (user didn't set the attribute), keep it null
	// regardless of what the API returns to avoid inconsistent result errors.
	if target.IsNull() {
		return
	}
	if source == nil {
		source = []string{}
	}
	list, _ := types.ListValueFrom(ctx, types.StringType, source)
	*target = list
}
