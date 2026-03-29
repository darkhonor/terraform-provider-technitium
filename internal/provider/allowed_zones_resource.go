// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &AllowedZonesResource{}

func NewAllowedZonesResource() resource.Resource {
	return &AllowedZonesResource{}
}

// AllowedZonesResource defines the resource implementation.
type AllowedZonesResource struct {
	client *client.Client
}

// AllowedZonesResourceModel describes the resource data model.
type AllowedZonesResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Domains types.Set    `tfsdk:"domains"`
}

func (r *AllowedZonesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowed_zones"
}

func (r *AllowedZonesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a set of Technitium DNS allowed zone entries.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Resource identifier (random UUID).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domains": schema.SetAttribute{
				Description: "Set of domain names to add to the allowed zone list.",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *AllowedZonesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AllowedZonesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AllowedZonesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var domains []string
	resp.Diagnostics.Append(plan.Domains.ElementsAs(ctx, &domains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, d := range domains {
		if _, err := checkAndSetCreate(ctx, r.client, d, FilterZoneAllowed); err != nil {
			resp.Diagnostics.AddError("Error creating allowed zone", err.Error())
			return
		}
	}

	id, err := uuid.GenerateUUID()
	if err != nil {
		resp.Diagnostics.AddError("Error generating resource ID", err.Error())
		return
	}
	plan.ID = types.StringValue(id)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AllowedZonesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AllowedZonesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateDomains []string
	resp.Diagnostics.Append(state.Domains.ElementsAs(ctx, &stateDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var existing []string
	for _, d := range stateDomains {
		exists, err := readDomainExists(ctx, r.client, d, FilterZoneAllowed)
		if err != nil {
			resp.Diagnostics.AddError("Error reading allowed zone", err.Error())
			return
		}
		if exists {
			existing = append(existing, d)
		}
	}

	if len(existing) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	newSet, diags := types.SetValueFrom(ctx, types.StringType, existing)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.Domains = newSet
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *AllowedZonesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var state AllowedZonesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var plan AllowedZonesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateDomains []string
	resp.Diagnostics.Append(state.Domains.ElementsAs(ctx, &stateDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planDomains []string
	resp.Diagnostics.Append(plan.Domains.ElementsAs(ctx, &planDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := reconcileSet(ctx, r.client, stateDomains, planDomains, FilterZoneAllowed); err != nil {
		resp.Diagnostics.AddError("Error updating allowed zones", err.Error())
		return
	}

	// Keep the same ID from state.
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AllowedZonesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AllowedZonesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var domains []string
	resp.Diagnostics.Append(state.Domains.ElementsAs(ctx, &domains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, d := range domains {
		if err := checkAndSetDelete(ctx, r.client, d, FilterZoneAllowed); err != nil {
			resp.Diagnostics.AddError("Error deleting allowed zone", err.Error())
			return
		}
	}
}
