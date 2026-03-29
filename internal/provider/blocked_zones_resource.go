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
var _ resource.Resource = &BlockedZonesResource{}

func NewBlockedZonesResource() resource.Resource {
	return &BlockedZonesResource{}
}

// BlockedZonesResource defines the resource implementation.
type BlockedZonesResource struct {
	client *client.Client
}

// BlockedZonesResourceModel describes the resource data model.
type BlockedZonesResourceModel struct {
	ID      types.String `tfsdk:"id"`
	Domains types.Set    `tfsdk:"domains"`
}

func (r *BlockedZonesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_blocked_zones"
}

func (r *BlockedZonesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a set of Technitium DNS blocked zone entries as a single resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Unique identifier for this blocked zones resource (random UUID, stable for resource lifetime).",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"domains": schema.SetAttribute{
				Description: "Set of domain names to block (e.g., [\"ads.example.com\", \"tracking.example.com\"]).",
				Required:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *BlockedZonesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *BlockedZonesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan BlockedZonesResourceModel
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
		if _, err := checkAndSetCreate(ctx, r.client, d, FilterZoneBlocked); err != nil {
			resp.Diagnostics.AddError("Error creating blocked zone", err.Error())
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

func (r *BlockedZonesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state BlockedZonesResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateDomains []string
	resp.Diagnostics.Append(state.Domains.ElementsAs(ctx, &stateDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var remaining []string
	for _, d := range stateDomains {
		exists, err := readDomainExists(ctx, r.client, d, FilterZoneBlocked)
		if err != nil {
			resp.Diagnostics.AddError("Error reading blocked zone", err.Error())
			return
		}
		if exists {
			remaining = append(remaining, d)
		}
	}

	if len(remaining) == 0 {
		resp.State.RemoveResource(ctx)
		return
	}

	domainsSet, diags := types.SetValueFrom(ctx, types.StringType, remaining)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state.Domains = domainsSet
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *BlockedZonesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state BlockedZonesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var planDomains []string
	resp.Diagnostics.Append(plan.Domains.ElementsAs(ctx, &planDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var stateDomains []string
	resp.Diagnostics.Append(state.Domains.ElementsAs(ctx, &stateDomains, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := reconcileSet(ctx, r.client, stateDomains, planDomains, FilterZoneBlocked); err != nil {
		resp.Diagnostics.AddError("Error updating blocked zones", err.Error())
		return
	}

	// Keep the same ID from state.
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *BlockedZonesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state BlockedZonesResourceModel
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
		if err := checkAndSetDelete(ctx, r.client, d, FilterZoneBlocked); err != nil {
			resp.Diagnostics.AddError("Error deleting blocked zone", err.Error())
			return
		}
	}
}
