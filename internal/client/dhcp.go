// Copyright (c) 2026 Stefano Bertelli
// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ErrDHCPScopeNotFound indicates the requested DHCP scope does not exist on the server.
var ErrDHCPScopeNotFound = errors.New("DHCP scope not found")

// DHCPStaticRoute is a classless static route (option 121) pushed to clients.
type DHCPStaticRoute struct {
	Destination string `json:"destination"`
	SubnetMask  string `json:"subnetMask"`
	Router      string `json:"router"`
}

// DHCPVendorInfo is a vendor-specific information entry (option 43).
type DHCPVendorInfo struct {
	Identifier  string `json:"identifier"`
	Information string `json:"information"`
}

// DHCPGenericOption is a raw DHCP option (code + hex value).
type DHCPGenericOption struct {
	Code  int    `json:"code"`
	Value string `json:"value"`
}

// DHCPExclusion is an address range excluded from dynamic allocation.
type DHCPExclusion struct {
	StartingAddress string `json:"startingAddress"`
	EndingAddress   string `json:"endingAddress"`
}

// DHCPReservedLease is a MAC-to-IP reservation within a scope.
type DHCPReservedLease struct {
	HostName        string `json:"hostName"`
	HardwareAddress string `json:"hardwareAddress"`
	Address         string `json:"address"`
	Comments        string `json:"comments"`
}

// DHCPScope is the full DHCP scope configuration from /api/dhcp/scopes/get.
type DHCPScope struct {
	Name                                 string              `json:"name"`
	StartingAddress                      string              `json:"startingAddress"`
	EndingAddress                        string              `json:"endingAddress"`
	SubnetMask                           string              `json:"subnetMask"`
	LeaseTimeDays                        int                 `json:"leaseTimeDays"`
	LeaseTimeHours                       int                 `json:"leaseTimeHours"`
	LeaseTimeMinutes                     int                 `json:"leaseTimeMinutes"`
	OfferDelayTime                       int                 `json:"offerDelayTime"`
	PingCheckEnabled                     bool                `json:"pingCheckEnabled"`
	PingCheckTimeout                     int                 `json:"pingCheckTimeout"`
	PingCheckRetries                     int                 `json:"pingCheckRetries"`
	DomainName                           string              `json:"domainName"`
	DomainSearchList                     []string            `json:"domainSearchList"`
	DNSUpdates                           bool                `json:"dnsUpdates"`
	DNSOverwriteForDynamicLease          bool                `json:"dnsOverwriteForDynamicLease"`
	DNSTTL                               int                 `json:"dnsTtl"`
	ServerAddress                        string              `json:"serverAddress"`
	ServerHostName                       string              `json:"serverHostName"`
	BootFileName                         string              `json:"bootFileName"`
	RouterAddress                        string              `json:"routerAddress"`
	UseThisDNSServer                     bool                `json:"useThisDnsServer"`
	DNSServers                           []string            `json:"dnsServers"`
	WINSServers                          []string            `json:"winsServers"`
	NTPServers                           []string            `json:"ntpServers"`
	NTPServerDomainNames                 []string            `json:"ntpServerDomainNames"`
	StaticRoutes                         []DHCPStaticRoute   `json:"staticRoutes"`
	VendorInfo                           []DHCPVendorInfo    `json:"vendorInfo"`
	CAPWAPAcIPAddresses                  []string            `json:"capwapAcIpAddresses"`
	TFTPServerAddresses                  []string            `json:"tftpServerAddresses"`
	GenericOptions                       []DHCPGenericOption `json:"genericOptions"`
	Exclusions                           []DHCPExclusion     `json:"exclusions"`
	ReservedLeases                       []DHCPReservedLease `json:"reservedLeases"`
	AllowOnlyReservedLeases              bool                `json:"allowOnlyReservedLeases"`
	BlockLocallyAdministeredMacAddresses bool                `json:"blockLocallyAdministeredMacAddresses"`
	IgnoreClientIdentifierOption         bool                `json:"ignoreClientIdentifierOption"`
}

// DHCPScopeSummary is a scope entry from /api/dhcp/scopes/list.
type DHCPScopeSummary struct {
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	StartingAddress  string `json:"startingAddress"`
	EndingAddress    string `json:"endingAddress"`
	SubnetMask       string `json:"subnetMask"`
	NetworkAddress   string `json:"networkAddress"`
	BroadcastAddress string `json:"broadcastAddress"`
}

// DHCPLease is a lease entry from /api/dhcp/leases/list.
type DHCPLease struct {
	Scope            string `json:"scope"`
	Type             string `json:"type"`
	HardwareAddress  string `json:"hardwareAddress"`
	ClientIdentifier string `json:"clientIdentifier"`
	Address          string `json:"address"`
	HostName         string `json:"hostName"`
	LeaseObtained    string `json:"leaseObtained"`
	LeaseExpires     string `json:"leaseExpires"`
}

// DHCPScopeList returns all DHCP scopes configured on the server.
func (c *Client) DHCPScopeList(ctx context.Context) ([]DHCPScopeSummary, error) {
	apiResp, err := c.doPost(ctx, "/api/dhcp/scopes/list", nil)
	if err != nil {
		return nil, fmt.Errorf("listing DHCP scopes: %w", err)
	}
	var listResp struct {
		Scopes []DHCPScopeSummary `json:"scopes"`
	}
	if err := json.Unmarshal(apiResp.Response, &listResp); err != nil {
		return nil, fmt.Errorf("decoding DHCP scope list response: %w", err)
	}
	return listResp.Scopes, nil
}

// DHCPScopeGet returns the full configuration of the named scope.
// Returns ErrDHCPScopeNotFound (wrapped) when the scope does not exist.
func (c *Client) DHCPScopeGet(ctx context.Context, name string) (*DHCPScope, error) {
	params := url.Values{}
	params.Set("name", name)
	apiResp, err := c.doPost(ctx, "/api/dhcp/scopes/get", params)
	if err != nil {
		if isDHCPScopeNotFoundErr(err) {
			return nil, fmt.Errorf("getting DHCP scope %q: %w", name, ErrDHCPScopeNotFound)
		}
		return nil, fmt.Errorf("getting DHCP scope %q: %w", name, err)
	}
	var scope DHCPScope
	if err := json.Unmarshal(apiResp.Response, &scope); err != nil {
		return nil, fmt.Errorf("decoding DHCP scope response: %w", err)
	}
	return &scope, nil
}

// DHCPScopeSet creates or updates a DHCP scope with the full desired state.
// Every parameter is always sent so removed values are cleared on the server
// rather than silently retained. newName, when non-empty, renames the scope.
//
// reservedLeases is the one exception to the always-send contract: the same
// server-side list is also managed by the standalone reserved-lease endpoints
// (DHCPScopeAddReservedLease / DHCPScopeRemoveReservedLease), so a scope
// update that always sent it would wipe reservations created that way. A nil
// ReservedLeases omits the parameter (server keeps its current list); a
// non-nil slice — including an empty one — sends it and overwrites.
func (c *Client) DHCPScopeSet(ctx context.Context, scope DHCPScope, newName string) error {
	params := url.Values{}
	params.Set("name", scope.Name)
	if newName != "" && newName != scope.Name {
		params.Set("newName", newName)
	}
	params.Set("startingAddress", scope.StartingAddress)
	params.Set("endingAddress", scope.EndingAddress)
	params.Set("subnetMask", scope.SubnetMask)
	params.Set("leaseTimeDays", strconv.Itoa(scope.LeaseTimeDays))
	params.Set("leaseTimeHours", strconv.Itoa(scope.LeaseTimeHours))
	params.Set("leaseTimeMinutes", strconv.Itoa(scope.LeaseTimeMinutes))
	params.Set("offerDelayTime", strconv.Itoa(scope.OfferDelayTime))
	params.Set("pingCheckEnabled", strconv.FormatBool(scope.PingCheckEnabled))
	params.Set("pingCheckTimeout", strconv.Itoa(scope.PingCheckTimeout))
	params.Set("pingCheckRetries", strconv.Itoa(scope.PingCheckRetries))
	params.Set("domainName", scope.DomainName)
	params.Set("domainSearchList", strings.Join(scope.DomainSearchList, ","))
	params.Set("dnsUpdates", strconv.FormatBool(scope.DNSUpdates))
	params.Set("dnsOverwriteForDynamicLease", strconv.FormatBool(scope.DNSOverwriteForDynamicLease))
	params.Set("dnsTtl", strconv.Itoa(scope.DNSTTL))
	params.Set("serverAddress", scope.ServerAddress)
	params.Set("serverHostName", scope.ServerHostName)
	params.Set("bootFileName", scope.BootFileName)
	params.Set("routerAddress", scope.RouterAddress)
	params.Set("useThisDnsServer", strconv.FormatBool(scope.UseThisDNSServer))
	params.Set("dnsServers", strings.Join(scope.DNSServers, ","))
	params.Set("winsServers", strings.Join(scope.WINSServers, ","))
	params.Set("ntpServers", strings.Join(scope.NTPServers, ","))
	params.Set("ntpServerDomainNames", strings.Join(scope.NTPServerDomainNames, ","))
	params.Set("staticRoutes", encodeDHCPStaticRoutes(scope.StaticRoutes))
	params.Set("vendorInfo", encodeDHCPVendorInfo(scope.VendorInfo))
	params.Set("capwapAcIpAddresses", strings.Join(scope.CAPWAPAcIPAddresses, ","))
	params.Set("tftpServerAddresses", strings.Join(scope.TFTPServerAddresses, ","))
	params.Set("genericOptions", encodeDHCPGenericOptions(scope.GenericOptions))
	params.Set("exclusions", encodeDHCPExclusions(scope.Exclusions))
	if scope.ReservedLeases != nil {
		params.Set("reservedLeases", encodeDHCPReservedLeases(scope.ReservedLeases))
	}
	params.Set("allowOnlyReservedLeases", strconv.FormatBool(scope.AllowOnlyReservedLeases))
	params.Set("blockLocallyAdministeredMacAddresses", strconv.FormatBool(scope.BlockLocallyAdministeredMacAddresses))
	params.Set("ignoreClientIdentifierOption", strconv.FormatBool(scope.IgnoreClientIdentifierOption))

	if _, err := c.doPost(ctx, "/api/dhcp/scopes/set", params); err != nil {
		return fmt.Errorf("setting DHCP scope %q: %w", scope.Name, err)
	}
	return nil
}

// DHCPScopeEnable enables the named scope so the server allocates leases from it.
func (c *Client) DHCPScopeEnable(ctx context.Context, name string) error {
	params := url.Values{}
	params.Set("name", name)
	if _, err := c.doPost(ctx, "/api/dhcp/scopes/enable", params); err != nil {
		return fmt.Errorf("enabling DHCP scope %q: %w", name, err)
	}
	return nil
}

// DHCPScopeDisable disables the named scope.
func (c *Client) DHCPScopeDisable(ctx context.Context, name string) error {
	params := url.Values{}
	params.Set("name", name)
	if _, err := c.doPost(ctx, "/api/dhcp/scopes/disable", params); err != nil {
		return fmt.Errorf("disabling DHCP scope %q: %w", name, err)
	}
	return nil
}

// DHCPScopeDelete deletes the named scope. Idempotent: deleting a scope that
// does not exist is not an error.
func (c *Client) DHCPScopeDelete(ctx context.Context, name string) error {
	params := url.Values{}
	params.Set("name", name)
	if _, err := c.doPost(ctx, "/api/dhcp/scopes/delete", params); err != nil {
		if isDHCPScopeNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("deleting DHCP scope %q: %w", name, err)
	}
	return nil
}

// DHCPScopeAddReservedLease adds a MAC-to-IP reservation to the named scope.
func (c *Client) DHCPScopeAddReservedLease(ctx context.Context, scopeName string, lease DHCPReservedLease) error {
	params := url.Values{}
	params.Set("name", scopeName)
	params.Set("hardwareAddress", lease.HardwareAddress)
	params.Set("ipAddress", lease.Address)
	if lease.HostName != "" {
		params.Set("hostName", lease.HostName)
	}
	if lease.Comments != "" {
		params.Set("comments", lease.Comments)
	}
	if _, err := c.doPost(ctx, "/api/dhcp/scopes/addReservedLease", params); err != nil {
		return fmt.Errorf("adding reserved lease %s to DHCP scope %q: %w", lease.HardwareAddress, scopeName, err)
	}
	return nil
}

// DHCPScopeRemoveReservedLease removes the reservation for the given MAC from the named scope.
func (c *Client) DHCPScopeRemoveReservedLease(ctx context.Context, scopeName, hardwareAddress string) error {
	params := url.Values{}
	params.Set("name", scopeName)
	params.Set("hardwareAddress", hardwareAddress)
	if _, err := c.doPost(ctx, "/api/dhcp/scopes/removeReservedLease", params); err != nil {
		return fmt.Errorf("removing reserved lease %s from DHCP scope %q: %w", hardwareAddress, scopeName, err)
	}
	return nil
}

// DHCPLeaseList returns all current leases across all scopes.
func (c *Client) DHCPLeaseList(ctx context.Context) ([]DHCPLease, error) {
	apiResp, err := c.doPost(ctx, "/api/dhcp/leases/list", nil)
	if err != nil {
		return nil, fmt.Errorf("listing DHCP leases: %w", err)
	}
	var listResp struct {
		Leases []DHCPLease `json:"leases"`
	}
	if err := json.Unmarshal(apiResp.Response, &listResp); err != nil {
		return nil, fmt.Errorf("decoding DHCP lease list response: %w", err)
	}
	return listResp.Leases, nil
}

// DHCPLeaseRemove removes a dynamic or reserved lease allocation.
func (c *Client) DHCPLeaseRemove(ctx context.Context, scopeName, hardwareAddress string) error {
	params := url.Values{}
	params.Set("name", scopeName)
	params.Set("hardwareAddress", hardwareAddress)
	if _, err := c.doPost(ctx, "/api/dhcp/leases/remove", params); err != nil {
		return fmt.Errorf("removing DHCP lease %s from scope %q: %w", hardwareAddress, scopeName, err)
	}
	return nil
}

// DHCPLeaseConvertToReserved converts a dynamic lease to a reserved lease.
func (c *Client) DHCPLeaseConvertToReserved(ctx context.Context, scopeName, hardwareAddress string) error {
	params := url.Values{}
	params.Set("name", scopeName)
	params.Set("hardwareAddress", hardwareAddress)
	if _, err := c.doPost(ctx, "/api/dhcp/leases/convertToReserved", params); err != nil {
		return fmt.Errorf("converting DHCP lease %s to reserved in scope %q: %w", hardwareAddress, scopeName, err)
	}
	return nil
}

// DHCPLeaseConvertToDynamic converts a reserved lease to a dynamic lease.
func (c *Client) DHCPLeaseConvertToDynamic(ctx context.Context, scopeName, hardwareAddress string) error {
	params := url.Values{}
	params.Set("name", scopeName)
	params.Set("hardwareAddress", hardwareAddress)
	if _, err := c.doPost(ctx, "/api/dhcp/leases/convertToDynamic", params); err != nil {
		return fmt.Errorf("converting DHCP lease %s to dynamic in scope %q: %w", hardwareAddress, scopeName, err)
	}
	return nil
}

// isDHCPScopeNotFoundErr reports whether err is a Technitium API error whose
// message indicates a missing DHCP scope.
func isDHCPScopeNotFoundErr(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	msg := strings.ToLower(apiErr.ErrorMessage)
	return strings.Contains(msg, "scope") && (strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist"))
}

// encodeDHCPStaticRoutes flattens routes into the API's pipe-separated wire
// format: dest|mask|router groups joined by |.
func encodeDHCPStaticRoutes(routes []DHCPStaticRoute) string {
	parts := make([]string, 0, len(routes)*3)
	for _, r := range routes {
		parts = append(parts, r.Destination, r.SubnetMask, r.Router)
	}
	return strings.Join(parts, "|")
}

// encodeDHCPVendorInfo flattens vendor info entries into identifier|information groups.
func encodeDHCPVendorInfo(entries []DHCPVendorInfo) string {
	parts := make([]string, 0, len(entries)*2)
	for _, v := range entries {
		parts = append(parts, v.Identifier, v.Information)
	}
	return strings.Join(parts, "|")
}

// encodeDHCPGenericOptions flattens options into code|value groups.
func encodeDHCPGenericOptions(opts []DHCPGenericOption) string {
	parts := make([]string, 0, len(opts)*2)
	for _, o := range opts {
		parts = append(parts, strconv.Itoa(o.Code), o.Value)
	}
	return strings.Join(parts, "|")
}

// encodeDHCPExclusions flattens exclusion ranges into start|end groups.
func encodeDHCPExclusions(exclusions []DHCPExclusion) string {
	parts := make([]string, 0, len(exclusions)*2)
	for _, e := range exclusions {
		parts = append(parts, e.StartingAddress, e.EndingAddress)
	}
	return strings.Join(parts, "|")
}

// encodeDHCPReservedLeases flattens reservations into host|mac|ip|comments groups.
func encodeDHCPReservedLeases(leases []DHCPReservedLease) string {
	parts := make([]string, 0, len(leases)*4)
	for _, l := range leases {
		parts = append(parts, l.HostName, l.HardwareAddress, l.Address, l.Comments)
	}
	return strings.Join(parts, "|")
}
