// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &SSOResource{}
	_ resource.ResourceWithImportState = &SSOResource{}
)

func NewSSOResource() resource.Resource {
	return &SSOResource{}
}

// SSOResource manages the server's Single Sign-On (OIDC) configuration.
// Singleton resource — one per provider instance. In a cluster, the SSO
// configuration is synchronized from the Primary node to all Secondary
// nodes, so managing it on the Primary covers the whole cluster.
type SSOResource struct {
	client *client.Client
}

type SSOResourceModel struct {
	ID                            types.String `tfsdk:"id"`
	Enabled                       types.Bool   `tfsdk:"enabled"`
	Authority                     types.String `tfsdk:"authority"`
	ClientID                      types.String `tfsdk:"client_id"`
	ClientSecret                  types.String `tfsdk:"client_secret"`
	MetadataAddress               types.String `tfsdk:"metadata_address"`
	Scopes                        types.List   `tfsdk:"scopes"`
	AllowSignup                   types.Bool   `tfsdk:"allow_signup"`
	AllowSignupOnlyForMappedUsers types.Bool   `tfsdk:"allow_signup_only_for_mapped_users"`
	GroupMap                      types.Map    `tfsdk:"group_map"`
}

func (r *SSOResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sso"
}

func (r *SSOResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages the Technitium DNS Server Single Sign-On (OpenID Connect) configuration. " +
			"Singleton resource — one per provider instance. In a cluster the SSO configuration " +
			"syncs from the Primary node to all Secondary nodes automatically.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Fixed identifier: sso.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				Description: "Enable Single Sign-On (SSO) with OpenID Connect (OIDC).",
				Required:    true,
			},
			"authority": schema.StringAttribute{
				Description: "The OpenID Connect (OIDC) Authority URL, e.g. https://keycloak.example.com/realms/master.",
				Optional:    true,
			},
			"client_id": schema.StringAttribute{
				Description: "The OpenID Connect (OIDC) Client ID.",
				Optional:    true,
			},
			"client_secret": schema.StringAttribute{
				Description: "The OpenID Connect (OIDC) Client Secret. The server never returns the real " +
					"secret, so drift in this attribute cannot be detected — the configured value is " +
					"authoritative.",
				Optional:  true,
				Sensitive: true,
			},
			"metadata_address": schema.StringAttribute{
				Description: "Custom OIDC metadata discovery URL. Only needed when the SSO provider uses " +
					"a non-default discovery URL.",
				Optional: true,
			},
			"scopes": schema.ListAttribute{
				Description: "OIDC scopes to request. Defaults to the server default (openid, profile, email) when unset.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"allow_signup": schema.BoolAttribute{
				Description: "Automatically provision user accounts for new users signing in via SSO.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"allow_signup_only_for_mapped_users": schema.BoolAttribute{
				Description: "Only allow new SSO users to sign up when they are a member of at least one " +
					"remote group mapped in group_map.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"group_map": schema.MapAttribute{
				Description: "Map of remote (OIDC provider) group names to local group names. SSO users' " +
					"local group membership is synced from this map on every login.",
				Optional:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *SSOResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *SSOResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan SSOResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.apply(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error configuring SSO", err.Error())
		return
	}

	plan.ID = types.StringValue("sso")
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading SSO config", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SSOResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state SSOResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readState(ctx, &state); err != nil {
		resp.Diagnostics.AddError("Error reading SSO config", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *SSOResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SSOResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.apply(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error updating SSO config", err.Error())
		return
	}

	plan.ID = types.StringValue("sso")
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading SSO config", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SSOResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Disable SSO on destroy; the stored provider settings remain on the
	// server but are inert.
	if _, err := r.client.SSOSet(ctx, map[string]string{"ssoEnabled": "false"}); err != nil {
		resp.Diagnostics.AddError("Error disabling SSO", err.Error())
	}
}

func (r *SSOResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// apply pushes the planned SSO configuration to the server.
func (r *SSOResource) apply(ctx context.Context, plan *SSOResourceModel) error {
	params := map[string]string{}

	params["ssoEnabled"] = fmt.Sprintf("%t", plan.Enabled.ValueBool())
	if !plan.Authority.IsNull() {
		params["ssoAuthority"] = plan.Authority.ValueString()
	}
	if !plan.ClientID.IsNull() {
		params["ssoClientId"] = plan.ClientID.ValueString()
	}
	if !plan.ClientSecret.IsNull() {
		params["ssoClientSecret"] = plan.ClientSecret.ValueString()
	}
	if !plan.MetadataAddress.IsNull() {
		params["ssoMetadataAddress"] = plan.MetadataAddress.ValueString()
	}
	if !plan.Scopes.IsNull() && !plan.Scopes.IsUnknown() {
		var scopes []string
		plan.Scopes.ElementsAs(ctx, &scopes, false)
		// ssoScopes is pipe-separated (unlike most list params, which use commas)
		params["ssoScopes"] = strings.Join(scopes, "|")
	}
	if !plan.AllowSignup.IsNull() && !plan.AllowSignup.IsUnknown() {
		params["ssoAllowSignup"] = fmt.Sprintf("%t", plan.AllowSignup.ValueBool())
	}
	if !plan.AllowSignupOnlyForMappedUsers.IsNull() && !plan.AllowSignupOnlyForMappedUsers.IsUnknown() {
		params["ssoAllowSignupOnlyForMappedUsers"] = fmt.Sprintf("%t", plan.AllowSignupOnlyForMappedUsers.ValueBool())
	}
	if !plan.GroupMap.IsNull() && !plan.GroupMap.IsUnknown() {
		params["ssoGroupMap"] = encodeGroupMap(ctx, plan.GroupMap)
	}

	_, err := r.client.SSOSet(ctx, params)
	return err
}

// encodeGroupMap converts the group_map attribute into the pipe-separated
// table format the API expects (remoteGroup|localGroup rows, flattened).
// Keys are sorted for a deterministic encoding.
func encodeGroupMap(ctx context.Context, groupMap types.Map) string {
	var entries map[string]string
	groupMap.ElementsAs(ctx, &entries, false)

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(entries)*2)
	for _, k := range keys {
		parts = append(parts, k, entries[k])
	}
	return strings.Join(parts, "|")
}

// readState refreshes the model from the server. The client secret is never
// returned by the API (always masked), so the state value is left untouched.
func (r *SSOResource) readState(ctx context.Context, model *SSOResourceModel) error {
	cfg, err := r.client.SSOGet(ctx)
	if err != nil {
		return err
	}

	model.ID = types.StringValue("sso")
	model.Enabled = types.BoolValue(cfg.SSOEnabled)
	model.Authority = stringPointerValue(cfg.SSOAuthority)
	model.ClientID = stringPointerValue(cfg.SSOClientID)
	model.MetadataAddress = stringPointerValue(cfg.SSOMetadataAddress)
	model.AllowSignup = types.BoolValue(cfg.SSOAllowSignup)
	model.AllowSignupOnlyForMappedUsers = types.BoolValue(cfg.SSOAllowSignupOnlyForMappedUsers)

	if !model.Scopes.IsNull() {
		scopes, _ := types.ListValueFrom(ctx, types.StringType, cfg.SSOScopes)
		model.Scopes = scopes
	}

	if !model.GroupMap.IsNull() {
		entries := map[string]string{}
		for _, e := range cfg.SSOGroupMap {
			entries[e.RemoteGroup] = e.LocalGroup
		}
		groupMap, _ := types.MapValueFrom(ctx, types.StringType, entries)
		model.GroupMap = groupMap
	}

	return nil
}

// stringPointerValue converts a *string into a types.String, mapping nil to
// null.
func stringPointerValue(s *string) types.String {
	if s == nil {
		return types.StringNull()
	}
	return types.StringValue(*s)
}
