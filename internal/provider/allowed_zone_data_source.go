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

var _ datasource.DataSource = &AllowedZoneDataSource{}

func NewAllowedZoneDataSource() datasource.DataSource {
	return &AllowedZoneDataSource{}
}

type AllowedZoneDataSource struct {
	client *client.Client
}

type AllowedZoneDataSourceModel struct {
	ID     types.String `tfsdk:"id"`
	Domain types.String `tfsdk:"domain"`
	Exists types.Bool   `tfsdk:"exists"`
}

func (d *AllowedZoneDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_allowed_zone"
}

func (d *AllowedZoneDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Checks whether a domain exists in the Technitium DNS allowed zone list.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true, Description: "Allowed zone identifier (same as domain)."},
			"domain": schema.StringAttribute{Required: true, Description: "The domain name to look up in the allowed zone list."},
			"exists": schema.BoolAttribute{Computed: true, Description: "True if the domain is present in the allowed zone list."},
		},
	}
}

func (d *AllowedZoneDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *AllowedZoneDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config AllowedZoneDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain := config.Domain.ValueString()

	exists, err := readDomainExists(ctx, d.client, domain, FilterZoneAllowed)
	if err != nil {
		resp.Diagnostics.AddError("Error reading allowed zone",
			fmt.Sprintf("Could not check allowed zone %q: %s", domain, err.Error()))
		return
	}

	state := AllowedZoneDataSourceModel{
		ID:     types.StringValue(domain),
		Domain: types.StringValue(domain),
		Exists: types.BoolValue(exists),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
