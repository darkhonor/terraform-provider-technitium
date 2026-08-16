// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &ClusterSecondaryResource{}
var _ resource.ResourceWithImportState = &ClusterSecondaryResource{}

// joinMutex serializes cluster join operations: joining multiple secondaries
// concurrently (e.g. a for_each over nodes) races on the primary's cluster
// config sync, so joins are performed one at a time per provider process.
var joinMutex sync.Mutex

func NewClusterSecondaryResource() resource.Resource {
	return &ClusterSecondaryResource{}
}

// ClusterSecondaryResource joins a Technitium DNS server to an existing
// cluster as a Secondary node. The provider itself must be configured
// against the cluster's Primary node; this resource makes its own API
// connection to the Secondary node being joined (node_url) because the
// initJoin call must be executed on the Secondary.
type ClusterSecondaryResource struct {
	client *client.Client
}

type ClusterSecondaryResourceModel struct {
	ID                      types.String `tfsdk:"id"`
	NodeURL                 types.String `tfsdk:"node_url"`
	NodeUsername            types.String `tfsdk:"node_username"`
	NodePassword            types.String `tfsdk:"node_password"`
	NodeToken               types.String `tfsdk:"node_token"`
	NodeSkipTLSVerify       types.Bool   `tfsdk:"node_skip_tls_verify"`
	NodeIPAddresses         types.List   `tfsdk:"node_ip_addresses"`
	PrimaryNodeURL          types.String `tfsdk:"primary_node_url"`
	PrimaryNodeIPAddress    types.String `tfsdk:"primary_node_ip_address"`
	PrimaryNodeUsername     types.String `tfsdk:"primary_node_username"`
	PrimaryNodePassword     types.String `tfsdk:"primary_node_password"`
	IgnoreCertificateErrors types.Bool   `tfsdk:"ignore_certificate_errors"`
	JoinTimeoutSeconds      types.Int64  `tfsdk:"join_timeout_seconds"`
	NodeName                types.String `tfsdk:"node_name"`
}

func (r *ClusterSecondaryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster_secondary"
}

func (r *ClusterSecondaryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Joins a Technitium DNS server to an existing cluster as a Secondary node. The " +
			"provider must be configured against the cluster's Primary node; this resource connects " +
			"directly to the Secondary node's API (node_url) to perform the join. Joining overwrites " +
			"the Secondary's Allowed, Blocked, Apps, Settings and Administration configuration with " +
			"the Primary's, and the credentials used for node_username/node_password stop working " +
			"when they are not present on the Primary — plan accordingly.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The Secondary node's DNS server domain name.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"node_url": schema.StringAttribute{
				Description: "API base URL of the Secondary node to join, e.g. http://10.0.0.11:5380.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					requiresReplaceUnlessAdopted(),
				},
			},
			"node_username": schema.StringAttribute{
				Description: "Administrator username on the Secondary node (used together with node_password when node_token is not set).",
				Optional:    true,
			},
			"node_password": schema.StringAttribute{
				Description: "Administrator password on the Secondary node.",
				Optional:    true,
				Sensitive:   true,
			},
			"node_token": schema.StringAttribute{
				Description: "API token on the Secondary node. Alternative to node_username/node_password.",
				Optional:    true,
				Sensitive:   true,
			},
			"node_skip_tls_verify": schema.BoolAttribute{
				Description: "Skip TLS certificate verification when connecting to the Secondary node " +
					"(e.g. while it still uses a self-signed certificate).",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"node_ip_addresses": schema.ListAttribute{
				Description: "Static IP addresses of the Secondary node, reachable by all other cluster nodes.",
				Required:    true,
				ElementType: types.StringType,
			},
			"primary_node_url": schema.StringAttribute{
				Description: "Web service HTTPS URL of the cluster's Primary node, e.g. https://dns01.example.com:53443/.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					requiresReplaceUnlessAdopted(),
				},
			},
			"primary_node_ip_address": schema.StringAttribute{
				Description: "IP address of the Primary node. When unset, the domain name in primary_node_url is resolved by the Secondary.",
				Optional:    true,
			},
			"primary_node_username": schema.StringAttribute{
				Description: "Username of an administrator on the Primary node, used once during the join.",
				Required:    true,
			},
			"primary_node_password": schema.StringAttribute{
				Description: "Password of the Primary node administrator, used once during the join.",
				Required:    true,
				Sensitive:   true,
			},
			"ignore_certificate_errors": schema.BoolAttribute{
				Description: "Set to true when the Primary node web service uses a self-signed TLS " +
					"certificate reachable on a private network.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"join_timeout_seconds": schema.Int64Attribute{
				Description: "Timeout for the join operation; the initial config sync can take a while.",
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(300),
			},
			"node_name": schema.StringAttribute{
				Description: "The Secondary node's DNS server domain name as reported after the join.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *ClusterSecondaryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// nodeClient builds an API client for the Secondary node from the resource's
// connection attributes.
func (r *ClusterSecondaryResource) nodeClient(ctx context.Context, model *ClusterSecondaryResourceModel) (*client.Client, error) {
	timeout := int(model.JoinTimeoutSeconds.ValueInt64())
	cfg := client.ClientConfig{
		BaseURL:        model.NodeURL.ValueString(),
		Token:          model.NodeToken.ValueString(),
		Username:       model.NodeUsername.ValueString(),
		Password:       model.NodePassword.ValueString(),
		SkipTLSVerify:  model.NodeSkipTLSVerify.ValueBool(),
		TimeoutSeconds: timeout,
	}
	nodeClient, err := client.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("configuring client for secondary node %q: %w", model.NodeURL.ValueString(), err)
	}
	if cfg.Token == "" {
		if err := nodeClient.Login(ctx); err != nil {
			return nil, fmt.Errorf("logging in to secondary node %q: %w", model.NodeURL.ValueString(), err)
		}
	}
	return nodeClient, nil
}

func (r *ClusterSecondaryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClusterSecondaryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nodeClient, err := r.nodeClient(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError("Error connecting to secondary node", err.Error())
		return
	}

	var ips []string
	resp.Diagnostics.Append(plan.NodeIPAddresses.ElementsAs(ctx, &ips, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	joinParams := client.ClusterInitJoinParams{
		SecondaryNodeIPAddresses: ips,
		PrimaryNodeURL:           plan.PrimaryNodeURL.ValueString(),
		PrimaryNodeIPAddress:     plan.PrimaryNodeIPAddress.ValueString(),
		IgnoreCertificateErrors:  plan.IgnoreCertificateErrors.ValueBool(),
		PrimaryNodeUsername:      plan.PrimaryNodeUsername.ValueString(),
		PrimaryNodePassword:      plan.PrimaryNodePassword.ValueString(),
	}

	joinMutex.Lock()
	defer joinMutex.Unlock()

	// Cluster initialization on the Primary enables HTTPS with a web service
	// restart, so the Primary's TLS endpoint may not accept connections for a
	// few seconds after technitium_cluster reports created — retry
	// connection-refused failures briefly instead of failing the join.
	var info *client.ClusterInfo
	deadline := time.Now().Add(90 * time.Second)
	for {
		info, err = nodeClient.ClusterInitJoin(ctx, joinParams)
		if err == nil || !isConnectionRefused(err) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			resp.Diagnostics.AddError("Error joining cluster", ctx.Err().Error())
			return
		case <-time.After(5 * time.Second):
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Error joining cluster", err.Error())
		return
	}

	plan.NodeName = types.StringValue(info.DNSServerDomain)
	plan.ID = types.StringValue(info.DNSServerDomain)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// isConnectionRefused reports whether the error looks like the target
// endpoint not accepting connections yet (either a transport error on the
// secondary, or the secondary reporting it could not reach the primary).
func isConnectionRefused(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset")
}

func (r *ClusterSecondaryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ClusterSecondaryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read via the Primary node (the provider's client): the node must appear
	// in the cluster state. Server versions that omit the node list from the
	// state endpoint keep the resource as-is.
	info, err := r.client.ClusterState(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Error reading cluster state", err.Error())
		return
	}
	if !info.ClusterInitialized {
		resp.State.RemoveResource(ctx)
		return
	}

	nodes := info.AllNodes()
	if len(nodes) > 0 {
		found := false
		for i := range nodes {
			if nodes[i].Name == state.NodeName.ValueString() {
				found = true
				break
			}
		}
		if !found {
			resp.State.RemoveResource(ctx)
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterSecondaryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ClusterSecondaryResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.NodeIPAddresses.Equal(state.NodeIPAddresses) {
		nodeClient, err := r.nodeClient(ctx, &plan)
		if err != nil {
			resp.Diagnostics.AddError("Error connecting to secondary node", err.Error())
			return
		}
		var ips []string
		resp.Diagnostics.Append(plan.NodeIPAddresses.ElementsAs(ctx, &ips, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if _, err := nodeClient.ClusterUpdateIPAddress(ctx, ips); err != nil {
			resp.Diagnostics.AddError("Error updating secondary node IP addresses", err.Error())
			return
		}
	}

	plan.ID = state.ID
	plan.NodeName = state.NodeName
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterSecondaryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ClusterSecondaryResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nodeClient, err := r.nodeClient(ctx, &state)
	if err == nil {
		if leaveErr := nodeClient.ClusterSecondaryLeave(ctx); leaveErr == nil {
			return
		} else {
			err = leaveErr
		}
	}

	// Fallback: remove the (unreachable) secondary via the Primary node.
	info, stateErr := r.client.ClusterState(ctx)
	if stateErr == nil {
		allNodes := info.AllNodes()
		for i := range allNodes {
			if allNodes[i].Name == state.NodeName.ValueString() && allNodes[i].Type == "Secondary" {
				if removeErr := r.client.ClusterRemoveSecondary(ctx, allNodes[i].ID); removeErr == nil {
					return
				}
				break
			}
		}
	}

	resp.Diagnostics.AddError("Error removing secondary node from cluster",
		fmt.Sprintf("leave via secondary failed (%s) and removal via primary did not succeed", err))
}

// requiresReplaceUnlessAdopted behaves like RequiresReplace, except that a
// null state value does not force a replacement: an imported (adopted)
// Secondary has only id/node_name in state, and filling the connection
// attributes from configuration is not a relocation of the node.
func requiresReplaceUnlessAdopted() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = !req.StateValue.IsNull()
		},
		"Replaces the node only when a previously known value changes; a null state value (fresh import) is filled in-place.",
		"Replaces the node only when a previously known value changes; a null state value (fresh import) is filled in-place.",
	)
}

func (r *ClusterSecondaryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import ID is the Secondary node's DNS server domain name as listed in
	// the cluster state (e.g. dns02.dns.example.com). Read() verifies the
	// membership against the Primary; the connection attributes are filled
	// from configuration on the next plan without forcing a replacement.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_name"), req.ID)...)
}
