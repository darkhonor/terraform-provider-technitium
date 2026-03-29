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

var _ datasource.DataSource = &BlockedZonesDataSource{}

func NewBlockedZonesDataSource() datasource.DataSource {
	return &BlockedZonesDataSource{}
}

type BlockedZonesDataSource struct {
	client *client.Client
}

type BlockedZonesDataSourceModel struct {
	ID      types.String `tfsdk:"id"`
	Domains types.Set    `tfsdk:"domains"`
}

func (d *BlockedZonesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_blocked_zones"
}

func (d *BlockedZonesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Retrieves the full list of domains in the Technitium DNS Server blocked zone list.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, Description: "Fixed identifier for this data source."},
			"domains": schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Set of all domain names in the blocked zone list."},
		},
	}
}

func (d *BlockedZonesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	providerData, ok := req.ProviderData.(*TechnitiumProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *TechnitiumProviderData, got: %T", req.ProviderData))
		return
	}
	d.client = providerData.Client
}

func (d *BlockedZonesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	domains, err := zoneList(ctx, d.client, FilterZoneBlocked)
	if err != nil {
		resp.Diagnostics.AddError("Error listing blocked zones", err.Error())
		return
	}

	domainsSet, diags := types.SetValueFrom(ctx, types.StringType, domains)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := BlockedZonesDataSourceModel{
		ID:      types.StringValue("blocked-zones"),
		Domains: domainsSet,
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
