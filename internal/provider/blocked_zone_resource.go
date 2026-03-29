// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

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
	_ resource.Resource                = &BlockedZoneResource{}
	_ resource.ResourceWithImportState = &BlockedZoneResource{}
)

func NewBlockedZoneResource() resource.Resource {
	return &BlockedZoneResource{}
}

// BlockedZoneResource defines the resource implementation.
type BlockedZoneResource struct {
	client *client.Client
}

// BlockedZoneResourceModel describes the resource data model.
type BlockedZoneResourceModel struct {
	ID     types.String `tfsdk:"id"`
	Domain types.String `tfsdk:"domain"`
}

func (r *BlockedZoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_blocked_zone"
}

func (r *BlockedZoneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Technitium DNS blocked zone entry.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Blocked zone identifier (same as domain).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "The domain name to block (e.g., ads.example.com).",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *BlockedZoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *BlockedZoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan BlockedZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := plan.Domain.ValueString()

	if _, err := checkAndSetCreate(ctx, r.client, domain, FilterZoneBlocked); err != nil {
		resp.Diagnostics.AddError("Error creating blocked zone", err.Error())
		return
	}

	plan.ID = types.StringValue(domain)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BlockedZoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state BlockedZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := state.Domain.ValueString()

	exists, err := readDomainExists(ctx, r.client, domain, FilterZoneBlocked)
	if err != nil {
		resp.Diagnostics.AddError("Error reading blocked zone", err.Error())
		return
	}
	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(domain)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *BlockedZoneResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"blocked_zone domain is immutable; this should not occur",
	)
}

func (r *BlockedZoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state BlockedZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := checkAndSetDelete(ctx, r.client, state.Domain.ValueString(), FilterZoneBlocked); err != nil {
		resp.Diagnostics.AddError("Error deleting blocked zone", err.Error())
	}
}

func (r *BlockedZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import by domain — set both attributes explicitly.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("domain"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
