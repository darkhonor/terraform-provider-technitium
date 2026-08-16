// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &APITokenResource{}

func NewAPITokenResource() resource.Resource {
	return &APITokenResource{}
}

// APITokenResource manages a non-expiring Technitium API token for a user.
// The token value is only available at creation time; it cannot be read back
// from the server afterwards.
type APITokenResource struct {
	client *client.Client
}

type APITokenResourceModel struct {
	ID           types.String `tfsdk:"id"`
	User         types.String `tfsdk:"user"`
	TokenName    types.String `tfsdk:"token_name"`
	Token        types.String `tfsdk:"token"`
	PartialToken types.String `tfsdk:"partial_token"`
}

func (r *APITokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_token"
}

func (r *APITokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Creates a non-expiring Technitium API token for a user, for use by automation. " +
			"The token value is only returned at creation time and is stored in Terraform state — " +
			"treat the state accordingly.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Identifier in the form user/token_name.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"user": schema.StringAttribute{
				Description: "The username to create the token for.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"token_name": schema.StringAttribute{
				Description: "Name for the token, unique per user.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"token": schema.StringAttribute{
				Description: "The API token value.",
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"partial_token": schema.StringAttribute{
				Description: "The partial token identifier used by the sessions API.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *APITokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *APITokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan APITokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token, err := r.client.CreateAPIToken(ctx, plan.User.ValueString(), plan.TokenName.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Error creating API token", err.Error())
		return
	}

	plan.ID = types.StringValue(fmt.Sprintf("%s/%s", token.Username, token.TokenName))
	plan.Token = types.StringValue(token.Token)
	plan.PartialToken = types.StringValue(r.findPartialToken(ctx, token))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// findPartialToken resolves the partial token for a freshly created token by
// listing sessions. Falls back to a token prefix when the session cannot be
// identified.
func (r *APITokenResource) findPartialToken(ctx context.Context, token *client.APIToken) string {
	sessions, err := r.client.SessionsList(ctx)
	if err == nil {
		for _, s := range sessions {
			if s.Type == "ApiToken" && s.Username == token.Username && s.TokenName == token.TokenName {
				return s.PartialToken
			}
		}
	}
	if len(token.Token) >= 16 {
		return token.Token[:16]
	}
	return token.Token
}

func (r *APITokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state APITokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	sessions, err := r.client.SessionsList(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error listing sessions", err.Error())
		return
	}

	for _, s := range sessions {
		if s.Type == "ApiToken" && s.Username == state.User.ValueString() && s.TokenName == state.TokenName.ValueString() {
			state.PartialToken = types.StringValue(s.PartialToken)
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}

	// Token no longer exists on the server.
	resp.State.RemoveResource(ctx)
}

func (r *APITokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// All attributes force replacement; Update is never called with changes.
	var plan APITokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *APITokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state APITokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.SessionDelete(ctx, state.PartialToken.ValueString()); err != nil {
		resp.Diagnostics.AddError("Error deleting API token", err.Error())
	}
}
