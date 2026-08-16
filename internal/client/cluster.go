// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ClusterNode represents a node in a Technitium cluster.
//
// Different API endpoints (and server versions) return the node addresses
// either as a list ("ipAddresses") or as a single value ("ipAddress"); both
// are captured and normalized via Addresses().
type ClusterNode struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	IPAddresses []string `json:"ipAddresses"`
	IPAddress   string   `json:"ipAddress"`
	Type        string   `json:"type"`
	State       string   `json:"state"`
	LastSeen    string   `json:"lastSeen"`
}

// Addresses returns the node's IP addresses regardless of which JSON shape
// the server used.
func (n *ClusterNode) Addresses() []string {
	if len(n.IPAddresses) > 0 {
		return n.IPAddresses
	}
	if n.IPAddress != "" {
		return []string{n.IPAddress}
	}
	return nil
}

// ClusterInfo represents the cluster state returned by the cluster endpoints.
//
// The node list is returned as "nodes" by the cluster endpoints and as
// "clusterNodes" by /api/user/login and /api/settings/get; both keys are
// captured and normalized via AllNodes().
type ClusterInfo struct {
	ClusterInitialized              bool          `json:"clusterInitialized"`
	DNSServerDomain                 string        `json:"dnsServerDomain"`
	ClusterDomain                   string        `json:"clusterDomain"`
	HeartbeatRefreshIntervalSeconds int           `json:"heartbeatRefreshIntervalSeconds"`
	ConfigRefreshIntervalSeconds    int           `json:"configRefreshIntervalSeconds"`
	Nodes                           []ClusterNode `json:"nodes"`
	ClusterNodes                    []ClusterNode `json:"clusterNodes"`
}

// AllNodes returns the cluster node list regardless of which JSON key the
// server used.
func (ci *ClusterInfo) AllNodes() []ClusterNode {
	if len(ci.Nodes) > 0 {
		return ci.Nodes
	}
	return ci.ClusterNodes
}

// FindNodeByURL returns the node whose web service URL matches the given URL
// (trailing-slash insensitive), or nil when no node matches.
func (ci *ClusterInfo) FindNodeByURL(nodeURL string) *ClusterNode {
	want := strings.TrimRight(nodeURL, "/")
	for i := range ci.AllNodes() {
		node := ci.AllNodes()[i]
		if strings.TrimRight(node.URL, "/") == want {
			return &node
		}
	}
	return nil
}

// ClusterState returns the current cluster state.
func (c *Client) ClusterState(ctx context.Context) (*ClusterInfo, error) {
	resp, err := c.doGet(ctx, "/api/admin/cluster/state", nil)
	if err != nil {
		return nil, fmt.Errorf("getting cluster state: %w", err)
	}

	var info ClusterInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("parsing cluster state response: %w", err)
	}
	return &info, nil
}

// ClusterInit initializes a new cluster with the current server as the
// Primary node.
func (c *Client) ClusterInit(ctx context.Context, clusterDomain string, primaryNodeIPAddresses []string) (*ClusterInfo, error) {
	params := url.Values{
		"clusterDomain":          {clusterDomain},
		"primaryNodeIpAddresses": {strings.Join(primaryNodeIPAddresses, ",")},
	}
	resp, err := c.doGet(ctx, "/api/admin/cluster/init", params)
	if err != nil {
		return nil, fmt.Errorf("initializing cluster %q: %w", clusterDomain, err)
	}

	var info ClusterInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("parsing cluster init response: %w", err)
	}
	return &info, nil
}

// ClusterPrimaryDelete deletes the cluster. This call can be made only at the
// Primary node. When force is true, the cluster is deleted even when
// Secondary nodes are still joined.
func (c *Client) ClusterPrimaryDelete(ctx context.Context, force bool) error {
	params := url.Values{
		"forceDelete": {strconv.FormatBool(force)},
	}
	_, err := c.doGet(ctx, "/api/admin/cluster/primary/delete", params)
	if err != nil {
		return fmt.Errorf("deleting cluster: %w", err)
	}
	return nil
}

// ClusterInitJoinParams holds the parameters for joining a cluster.
type ClusterInitJoinParams struct {
	SecondaryNodeIPAddresses []string
	PrimaryNodeURL           string
	PrimaryNodeIPAddress     string
	IgnoreCertificateErrors  bool
	PrimaryNodeUsername      string
	PrimaryNodePassword      string
	PrimaryNodeTotp          string
}

// ClusterInitJoin joins the current server to an existing cluster as a
// Secondary node. This call must be made against the Secondary node's API.
func (c *Client) ClusterInitJoin(ctx context.Context, p ClusterInitJoinParams) (*ClusterInfo, error) {
	params := url.Values{
		"secondaryNodeIpAddresses": {strings.Join(p.SecondaryNodeIPAddresses, ",")},
		"primaryNodeUrl":           {p.PrimaryNodeURL},
		"primaryNodeUsername":      {p.PrimaryNodeUsername},
		"primaryNodePassword":      {p.PrimaryNodePassword},
	}
	if p.PrimaryNodeIPAddress != "" {
		params.Set("primaryNodeIpAddress", p.PrimaryNodeIPAddress)
	}
	if p.IgnoreCertificateErrors {
		params.Set("ignoreCertificateErrors", "true")
	}
	if p.PrimaryNodeTotp != "" {
		params.Set("primaryNodeTotp", p.PrimaryNodeTotp)
	}

	resp, err := c.doPost(ctx, "/api/admin/cluster/initJoin", params)
	if err != nil {
		return nil, fmt.Errorf("joining cluster at %q: %w", p.PrimaryNodeURL, err)
	}

	var info ClusterInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("parsing cluster join response: %w", err)
	}
	return &info, nil
}

// ClusterSecondaryLeave gracefully removes the current server from the
// cluster. This call can be made only at a Secondary node.
func (c *Client) ClusterSecondaryLeave(ctx context.Context) error {
	_, err := c.doGet(ctx, "/api/admin/cluster/secondary/leave", nil)
	if err != nil {
		return fmt.Errorf("leaving cluster: %w", err)
	}
	return nil
}

// ClusterRemoveSecondary removes an unreachable Secondary node from the
// cluster. This call can be made only at the Primary node.
func (c *Client) ClusterRemoveSecondary(ctx context.Context, secondaryNodeID int64) error {
	params := url.Values{
		"secondaryNodeId": {strconv.FormatInt(secondaryNodeID, 10)},
	}
	_, err := c.doGet(ctx, "/api/admin/cluster/primary/removeSecondary", params)
	if err != nil {
		return fmt.Errorf("removing secondary node %d: %w", secondaryNodeID, err)
	}
	return nil
}

// ClusterUpdateIPAddress updates the current node's IP addresses.
func (c *Client) ClusterUpdateIPAddress(ctx context.Context, ipAddresses []string) (*ClusterInfo, error) {
	params := url.Values{
		"ipAddresses": {strings.Join(ipAddresses, ",")},
	}
	resp, err := c.doGet(ctx, "/api/admin/cluster/updateIpAddress", params)
	if err != nil {
		return nil, fmt.Errorf("updating cluster node IP addresses: %w", err)
	}

	var info ClusterInfo
	if err := json.Unmarshal(resp.Response, &info); err != nil {
		return nil, fmt.Errorf("parsing cluster updateIpAddress response: %w", err)
	}
	return &info, nil
}
