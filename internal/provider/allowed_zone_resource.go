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
	_ resource.Resource                = &AllowedZoneResource{}
	_ resource.ResourceWithImportState = &AllowedZoneResource{}
)

func NewAllowedZoneResource() resource.Resource {
	return &AllowedZoneResource{}
}

// AllowedZoneResource defines the resource implementation.
type AllowedZoneResource struct {
	client *client.Client
}

// AllowedZoneResourceModel describes the resource data model.
type AllowedZoneResourceModel struct {
	ID     types.String `tfsdk:"id"`
	Domain types.String `tfsdk:"domain"`
}

func (r *AllowedZoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowed_zone"
}

func (r *AllowedZoneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Technitium DNS allowed zone entry.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Allowed zone identifier (same as domain).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domain": schema.StringAttribute{
				Description: "The domain name to add to the allowed zone list.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *AllowedZoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AllowedZoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AllowedZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := plan.Domain.ValueString()

	if _, err := checkAndSetCreate(ctx, r.client, domain, FilterZoneAllowed); err != nil {
		resp.Diagnostics.AddError("Error creating allowed zone", err.Error())
		return
	}

	plan.ID = types.StringValue(domain)
	plan.Domain = types.StringValue(domain)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AllowedZoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AllowedZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := state.Domain.ValueString()

	exists, err := readDomainExists(ctx, r.client, domain, FilterZoneAllowed)
	if err != nil {
		resp.Diagnostics.AddError("Error reading allowed zone", err.Error())
		return
	}

	if !exists {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(domain)
	state.Domain = types.StringValue(domain)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *AllowedZoneResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported",
		"The allowed_zone resource does not support in-place updates. The domain attribute forces resource replacement.")
}

func (r *AllowedZoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AllowedZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := checkAndSetDelete(ctx, r.client, state.Domain.ValueString(), FilterZoneAllowed); err != nil {
		resp.Diagnostics.AddError("Error deleting allowed zone", err.Error())
	}
}

func (r *AllowedZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("domain"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
