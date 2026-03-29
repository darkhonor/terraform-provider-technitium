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

var _ datasource.DataSource = &AllowedZonesDataSource{}

func NewAllowedZonesDataSource() datasource.DataSource {
	return &AllowedZonesDataSource{}
}

type AllowedZonesDataSource struct {
	client *client.Client
}

type AllowedZonesDataSourceModel struct {
	ID      types.String `tfsdk:"id"`
	Domains types.Set    `tfsdk:"domains"`
}

func (d *AllowedZonesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowed_zones"
}

func (d *AllowedZonesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Returns the full list of domains in the Technitium DNS allowed zone list.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true, Description: "Data source identifier (always \"allowed-zones\")."},
			"domains": schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Set of all domains present in the allowed zone list."},
		},
	}
}

func (d *AllowedZonesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AllowedZonesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config AllowedZonesDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domains, err := zoneList(ctx, d.client, FilterZoneAllowed)
	if err != nil {
		resp.Diagnostics.AddError("Error listing allowed zones",
			fmt.Sprintf("Could not retrieve allowed zone list: %s", err.Error()))
		return
	}

	domainSet, diags := types.SetValueFrom(ctx, types.StringType, domains)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	state := AllowedZonesDataSourceModel{
		ID:      types.StringValue("allowed-zones"),
		Domains: domainSet,
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
