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

var _ datasource.DataSource = &BlockedZoneDataSource{}

func NewBlockedZoneDataSource() datasource.DataSource {
	return &BlockedZoneDataSource{}
}

type BlockedZoneDataSource struct {
	client *client.Client
}

type BlockedZoneDataSourceModel struct {
	ID     types.String `tfsdk:"id"`
	Domain types.String `tfsdk:"domain"`
	Exists types.Bool   `tfsdk:"exists"`
}

func (d *BlockedZoneDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_blocked_zone"
}

func (d *BlockedZoneDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Checks whether a domain exists in the Technitium DNS Server blocked zone list.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, Description: "Blocked zone identifier (same as domain)."},
			"domain": schema.StringAttribute{Required: true, Description: "The domain name to check in the blocked zone list."},
			"exists": schema.BoolAttribute{Computed: true, Description: "True if the domain is present in the blocked zone list."},
		},
	}
}

func (d *BlockedZoneDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *BlockedZoneDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config BlockedZoneDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := config.Domain.ValueString()
	exists, err := readDomainExists(ctx, d.client, domain, FilterZoneBlocked)
	if err != nil {
		resp.Diagnostics.AddError("Error checking blocked zone",
			fmt.Sprintf("Could not check blocked zone %q: %s", domain, err.Error()))
		return
	}

	state := BlockedZoneDataSourceModel{
		ID:     types.StringValue(domain),
		Domain: types.StringValue(domain),
		Exists: types.BoolValue(exists),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
