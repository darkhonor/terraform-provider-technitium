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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &UserResource{}
	_ resource.ResourceWithImportState = &UserResource{}
)

func NewUserResource() resource.Resource {
	return &UserResource{}
}

// UserResource manages a local Technitium user account. SSO-provisioned
// users are managed by the SSO provider and should not be managed with this
// resource.
type UserResource struct {
	client *client.Client
}

type UserResourceModel struct {
	ID                    types.String `tfsdk:"id"`
	Username              types.String `tfsdk:"username"`
	Password              types.String `tfsdk:"password"`
	DisplayName           types.String `tfsdk:"display_name"`
	MemberOfGroups        types.Set    `tfsdk:"member_of_groups"`
	SessionTimeoutSeconds types.Int64  `tfsdk:"session_timeout_seconds"`
	Disabled              types.Bool   `tfsdk:"disabled"`
}

func (r *UserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *UserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a local Technitium user account. In a cluster, users sync from the " +
			"Primary node to all Secondary nodes automatically.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The username.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"username": schema.StringAttribute{
				Description: "The account username.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"password": schema.StringAttribute{
				Description: "The account password. The server never returns passwords, so drift in " +
					"this attribute cannot be detected — the configured value is authoritative.",
				Required:  true,
				Sensitive: true,
			},
			"display_name": schema.StringAttribute{
				Description: "Display name for the account. Removing a previously set value resets it to " +
					"the server default.",
				Optional: true,
			},
			"member_of_groups": schema.SetAttribute{
				Description: "Groups the user is a member of, e.g. Administrators, DNS Administrators. " +
					"When unset, group membership is left unmanaged.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"session_timeout_seconds": schema.Int64Attribute{
				Description: "Session timeout in seconds.",
				Optional:    true,
				Computed:    true,
			},
			"disabled": schema.BoolAttribute{
				Description: "Disable the account.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
		},
	}
}

func (r *UserResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *UserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan UserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	username := plan.Username.ValueString()

	// Build the follow-up parameters from the plan before the account is
	// refreshed below: readState overwrites the configured values with the
	// server's, which would send the server's own values back to it.
	params := r.buildSetParams(ctx, &plan)

	if err := r.client.UserCreate(ctx, username, plan.Password.ValueString(), plan.DisplayName.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error creating user", err.Error())
		return
	}

	// The account exists on the server from here on. Persist state before any
	// further call so a later failure surfaces on a resource Terraform tracks,
	// rather than orphaning a live account that the next apply cannot recreate
	// ("user already exists") and cannot destroy.
	plan.ID = types.StringValue(username)
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(params) > 0 {
		if err := r.client.UserSet(ctx, username, params); err != nil {
			resp.Diagnostics.AddError("Error configuring user", err.Error())
			return
		}
		if err := r.readState(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("Error reading user", err.Error())
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *UserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.readState(ctx, &state); err != nil {
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && strings.Contains(strings.ToLower(apiErr.ErrorMessage), "no such user") {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Error reading user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *UserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state UserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := r.buildSetParams(ctx, &plan)
	if !plan.Password.Equal(state.Password) {
		params["newPass"] = plan.Password.ValueString()
	}
	if !plan.DisplayName.IsNull() {
		params["displayName"] = plan.DisplayName.ValueString()
	} else if !state.DisplayName.IsNull() {
		// Omitting displayName makes the server retain the stored value, so a
		// display name removed from configuration must be reset explicitly.
		params["displayName"] = ""
	}

	if len(params) > 0 {
		if err := r.client.UserSet(ctx, plan.Username.ValueString(), params); err != nil {
			resp.Diagnostics.AddError("Error updating user", err.Error())
			return
		}
	}

	plan.ID = state.ID
	if err := r.readState(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Error reading user", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *UserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.UserDelete(ctx, state.Username.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting user", err.Error())
	}
}

func (r *UserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("username"), req.ID)...)
}

// buildSetParams builds /api/admin/users/set params for attributes that are
// configured beyond the create call. Password changes are handled separately
// in Update.
func (r *UserResource) buildSetParams(ctx context.Context, plan *UserResourceModel) map[string]string {
	params := map[string]string{}

	if !plan.MemberOfGroups.IsNull() && !plan.MemberOfGroups.IsUnknown() {
		var groups []string
		plan.MemberOfGroups.ElementsAs(ctx, &groups, false)
		params["memberOfGroups"] = strings.Join(groups, ",")
	}
	if !plan.SessionTimeoutSeconds.IsNull() && !plan.SessionTimeoutSeconds.IsUnknown() {
		params["sessionTimeoutSeconds"] = fmt.Sprintf("%d", plan.SessionTimeoutSeconds.ValueInt64())
	}
	if !plan.Disabled.IsNull() && !plan.Disabled.IsUnknown() {
		params["disabled"] = fmt.Sprintf("%t", plan.Disabled.ValueBool())
	}

	return params
}

// readState refreshes the model from the server. The password is never
// returned by the API, so the state value is left untouched.
func (r *UserResource) readState(ctx context.Context, model *UserResourceModel) error {
	user, err := r.client.UserGet(ctx, model.Username.ValueString())
	if err != nil {
		return err
	}

	model.ID = types.StringValue(user.Username)
	model.Username = types.StringValue(user.Username)
	model.Disabled = types.BoolValue(user.Disabled)
	model.SessionTimeoutSeconds = types.Int64Value(int64(user.SessionTimeoutSeconds))
	// display_name is only read back when configured: when it is unset the
	// server substitutes its own default (the username), and reading that back
	// would turn a null plan into a concrete value.
	if !model.DisplayName.IsNull() {
		model.DisplayName = types.StringValue(user.DisplayName)
	}
	if !model.MemberOfGroups.IsNull() {
		groups, _ := types.SetValueFrom(ctx, types.StringType, user.MemberOfGroups)
		model.MemberOfGroups = groups
	}
	return nil
}
