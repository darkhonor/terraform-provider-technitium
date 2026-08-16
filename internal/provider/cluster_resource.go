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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &ClusterResource{}
	_ resource.ResourceWithImportState = &ClusterResource{}
)

func NewClusterResource() resource.Resource {
	return &ClusterResource{}
}

// ClusterResource initializes Technitium native clustering with the
// provider's server as the Primary node. Singleton resource — one per
// provider instance. Secondary nodes join via technitium_cluster_secondary.
type ClusterResource struct {
	client *client.Client
}

type ClusterResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	ClusterDomain          types.String `tfsdk:"cluster_domain"`
	PrimaryNodeIPAddresses types.List   `tfsdk:"primary_node_ip_addresses"`
	ForceDelete            types.Bool   `tfsdk:"force_delete"`
	DNSServerDomain        types.String `tfsdk:"dns_server_domain"`
}

func (r *ClusterResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *ClusterResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Initializes Technitium native clustering (v14+) with the provider's server as the " +
			"Primary node. The cluster domain cannot be changed after initialization. Initialization " +
			"creates the cluster Primary zone and the cluster Catalog zone " +
			"(cluster-catalog.<cluster_domain>) automatically, and enables HTTPS on the web service " +
			"with a self-signed certificate when HTTPS is not already configured — configure a valid " +
			"TLS certificate via technitium_server_settings before creating this resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The cluster domain.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cluster_domain": schema.StringAttribute{
				Description: "Fully qualified domain name identifying the cluster. Cannot be changed " +
					"after initialization.",
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"primary_node_ip_addresses": schema.ListAttribute{
				Description: "Static IP addresses of this server, reachable by all Secondary nodes.",
				Required:    true,
				ElementType: types.StringType,
			},
			"force_delete": schema.BoolAttribute{
				Description: "Delete the cluster on destroy even when Secondary nodes are still joined.",
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"dns_server_domain": schema.StringAttribute{
				Description: "The Primary node's DNS server domain name.",
				Computed:    true,
			},
		},
	}
}

func (r *ClusterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ClusterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClusterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var ips []string
	resp.Diagnostics.Append(plan.PrimaryNodeIPAddresses.ElementsAs(ctx, &ips, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	info, err := r.client.ClusterInit(ctx, plan.ClusterDomain.ValueString(), ips)
	if err != nil {
		resp.Diagnostics.AddError("Error initializing cluster", err.Error())
		return
	}

	plan.ID = types.StringValue(plan.ClusterDomain.ValueString())
	plan.DNSServerDomain = types.StringValue(info.DNSServerDomain)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ClusterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	info, err := r.client.ClusterState(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading cluster state", err.Error())
		return
	}

	if !info.ClusterInitialized {
		resp.State.RemoveResource(ctx)
		return
	}

	state.ID = types.StringValue(info.ClusterDomain)
	state.ClusterDomain = types.StringValue(info.ClusterDomain)
	if info.DNSServerDomain != "" {
		state.DNSServerDomain = types.StringValue(info.DNSServerDomain)
	} else if state.DNSServerDomain.IsNull() || state.DNSServerDomain.IsUnknown() {
		state.DNSServerDomain = types.StringValue("")
	}

	// Refresh the primary node IPs when the node list is available; some
	// server versions omit the node list from the state endpoint, in which
	// case the stored value is kept.
	nodes := info.AllNodes()
	for i := range nodes {
		if nodes[i].Type == "Primary" {
			if addrs := nodes[i].Addresses(); len(addrs) > 0 {
				ipList, diags := types.ListValueFrom(ctx, types.StringType, addrs)
				resp.Diagnostics.Append(diags...)
				state.PrimaryNodeIPAddresses = ipList
			}
			break
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ClusterResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.PrimaryNodeIPAddresses.Equal(state.PrimaryNodeIPAddresses) {
		var ips []string
		resp.Diagnostics.Append(plan.PrimaryNodeIPAddresses.ElementsAs(ctx, &ips, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if _, err := r.client.ClusterUpdateIPAddress(ctx, ips); err != nil {
			resp.Diagnostics.AddError("Error updating primary node IP addresses", err.Error())
			return
		}
	}

	plan.ID = state.ID
	plan.DNSServerDomain = state.DNSServerDomain
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ClusterResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.ClusterPrimaryDelete(ctx, state.ForceDelete.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Error deleting cluster", err.Error())
	}
}

func (r *ClusterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cluster_domain"), req.ID)...)
}
