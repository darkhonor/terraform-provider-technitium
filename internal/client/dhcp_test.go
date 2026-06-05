// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestDHCPScopeList(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/dhcp/scopes/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"scopes":[{"name":"Default","enabled":true,"startingAddress":"192.168.1.1","endingAddress":"192.168.1.254","subnetMask":"255.255.255.0","networkAddress":"192.168.1.0","broadcastAddress":"192.168.1.255"}]}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	scopes, err := c.DHCPScopeList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scopes) != 1 || scopes[0].Name != "Default" || !scopes[0].Enabled {
		t.Errorf("unexpected scopes: %+v", scopes)
	}
}

func TestDHCPScopeGet(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/dhcp/scopes/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.FormValue("name") != "Default" {
			t.Errorf("expected name=Default, got %q", r.FormValue("name"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status: "ok",
			Response: json.RawMessage(`{
				"name":"Default","startingAddress":"192.168.1.1","endingAddress":"192.168.1.254","subnetMask":"255.255.255.0",
				"leaseTimeDays":7,"domainName":"local","domainSearchList":["home.arpa"],"dnsUpdates":true,"dnsTtl":900,
				"routerAddress":"192.168.1.1","useThisDnsServer":false,"dnsServers":["192.168.1.5"],
				"staticRoutes":[{"destination":"172.16.0.0","subnetMask":"255.255.255.0","router":"192.168.1.2"}],
				"genericOptions":[{"code":150,"value":"C0:A8:01:01"}],
				"exclusions":[{"startingAddress":"192.168.1.1","endingAddress":"192.168.1.10"}],
				"reservedLeases":[{"hostName":null,"hardwareAddress":"00-11-22-33-44-55","address":"192.168.1.10","comments":"x"}],
				"allowOnlyReservedLeases":false}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	scope, err := c.DHCPScopeGet(context.Background(), "Default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope.LeaseTimeDays != 7 || scope.DomainName != "local" || scope.DNSTTL != 900 {
		t.Errorf("unexpected scope fields: %+v", scope)
	}
	if len(scope.StaticRoutes) != 1 || scope.StaticRoutes[0].Router != "192.168.1.2" {
		t.Errorf("unexpected static routes: %+v", scope.StaticRoutes)
	}
	if len(scope.GenericOptions) != 1 || scope.GenericOptions[0].Code != 150 {
		t.Errorf("unexpected generic options: %+v", scope.GenericOptions)
	}
	if len(scope.ReservedLeases) != 1 || scope.ReservedLeases[0].HardwareAddress != "00-11-22-33-44-55" {
		t.Errorf("unexpected reserved leases: %+v", scope.ReservedLeases)
	}
}

func TestDHCPScopeGet_NotFound(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "DHCP scope was not found: nope",
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	_, err := c.DHCPScopeGet(context.Background(), "nope")
	if !errors.Is(err, ErrDHCPScopeNotFound) {
		t.Fatalf("expected ErrDHCPScopeNotFound, got %v", err)
	}
}

func TestDHCPScopeSet_WireFormat(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/dhcp/scopes/set" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		checks := map[string]string{
			"name":             "lan",
			"newName":          "lan2",
			"startingAddress":  "10.0.0.50",
			"endingAddress":    "10.0.0.250",
			"subnetMask":       "255.255.255.0",
			"leaseTimeDays":    "7",
			"leaseTimeHours":   "0",
			"domainSearchList": "a.example,b.example",
			"dnsServers":       "10.0.0.5,10.0.0.6",
			"staticRoutes":     "172.16.0.0|255.255.255.0|10.0.0.2|172.17.0.0|255.255.0.0|10.0.0.3",
			"exclusions":       "10.0.0.60|10.0.0.70",
			"reservedLeases":   "host1|00-11-22-33-44-55|10.0.0.100|note",
			"genericOptions":   "150|C0:A8:01:01",
			"vendorInfo":       "id1|AA:BB",
			"dnsUpdates":       "true",
			"pingCheckEnabled": "false",
		}
		for k, want := range checks {
			if got := r.FormValue(k); got != want {
				t.Errorf("param %s: got %q, want %q", k, got, want)
			}
		}
		// Always-send contract: clearing params must be present even when empty.
		for _, k := range []string{"domainName", "routerAddress", "winsServers", "ntpServers"} {
			if !r.PostForm.Has(k) {
				t.Errorf("param %s must always be sent (empty clears server value)", k)
			}
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	err := c.DHCPScopeSet(context.Background(), DHCPScope{
		Name:             "lan",
		StartingAddress:  "10.0.0.50",
		EndingAddress:    "10.0.0.250",
		SubnetMask:       "255.255.255.0",
		LeaseTimeDays:    7,
		DomainSearchList: []string{"a.example", "b.example"},
		DNSUpdates:       true,
		DNSServers:       []string{"10.0.0.5", "10.0.0.6"},
		StaticRoutes: []DHCPStaticRoute{
			{Destination: "172.16.0.0", SubnetMask: "255.255.255.0", Router: "10.0.0.2"},
			{Destination: "172.17.0.0", SubnetMask: "255.255.0.0", Router: "10.0.0.3"},
		},
		VendorInfo:     []DHCPVendorInfo{{Identifier: "id1", Information: "AA:BB"}},
		GenericOptions: []DHCPGenericOption{{Code: 150, Value: "C0:A8:01:01"}},
		Exclusions:     []DHCPExclusion{{StartingAddress: "10.0.0.60", EndingAddress: "10.0.0.70"}},
		ReservedLeases: []DHCPReservedLease{{HostName: "host1", HardwareAddress: "00-11-22-33-44-55", Address: "10.0.0.100", Comments: "note"}},
	}, "lan2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDHCPScopeSet_NoRenameOmitsNewName(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.PostForm == nil {
			_ = r.ParseForm()
		}
		if r.PostForm.Has("newName") {
			t.Error("newName must be omitted when not renaming")
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.DHCPScopeSet(context.Background(), DHCPScope{Name: "lan", StartingAddress: "10.0.0.50", EndingAddress: "10.0.0.250", SubnetMask: "255.255.255.0"}, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDHCPScopeEnableDisableDelete(t *testing.T) {
	var gotPaths []string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		if r.FormValue("name") != "lan" {
			t.Errorf("expected name=lan, got %q", r.FormValue("name"))
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	ctx := context.Background()
	if err := c.DHCPScopeEnable(ctx, "lan"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := c.DHCPScopeDisable(ctx, "lan"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := c.DHCPScopeDelete(ctx, "lan"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	want := []string{"/api/dhcp/scopes/enable", "/api/dhcp/scopes/disable", "/api/dhcp/scopes/delete"}
	for i, p := range want {
		if gotPaths[i] != p {
			t.Errorf("call %d: got %s, want %s", i, gotPaths[i], p)
		}
	}
}

func TestDHCPScopeDelete_NotFoundIsIdempotent(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:       "error",
			ErrorMessage: "DHCP scope does not exist: gone",
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err := c.DHCPScopeDelete(context.Background(), "gone"); err != nil {
		t.Fatalf("expected idempotent delete, got %v", err)
	}
}

func TestDHCPScopeAddRemoveReservedLease(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/dhcp/scopes/addReservedLease":
			if r.FormValue("hardwareAddress") != "00-11-22-33-44-55" || r.FormValue("ipAddress") != "10.0.0.100" {
				t.Errorf("unexpected add params: %v", r.PostForm)
			}
			if r.FormValue("hostName") != "host1" || r.FormValue("comments") != "note" {
				t.Errorf("expected optional params, got: %v", r.PostForm)
			}
		case "/api/dhcp/scopes/removeReservedLease":
			if r.FormValue("hardwareAddress") != "00-11-22-33-44-55" {
				t.Errorf("unexpected remove params: %v", r.PostForm)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	ctx := context.Background()
	lease := DHCPReservedLease{HostName: "host1", HardwareAddress: "00-11-22-33-44-55", Address: "10.0.0.100", Comments: "note"}
	if err := c.DHCPScopeAddReservedLease(ctx, "lan", lease); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := c.DHCPScopeRemoveReservedLease(ctx, "lan", "00-11-22-33-44-55"); err != nil {
		t.Fatalf("remove: %v", err)
	}
}

func TestDHCPLeaseList(t *testing.T) {
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/dhcp/leases/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{
			Status:   "ok",
			Response: json.RawMessage(`{"leases":[{"scope":"Default","type":"Reserved","hardwareAddress":"00-11-22-33-44-55","clientIdentifier":"1-001122334455","address":"192.168.1.5","hostName":"server1.local","leaseObtained":"08/25/2020 17:52:51","leaseExpires":"09/26/2020 14:27:12"},{"scope":"Default","type":"Dynamic","hardwareAddress":"66-77-88-99-AA-BB","clientIdentifier":"1-66778899aabb","address":"192.168.1.13","hostName":null,"leaseObtained":"06/15/2020 16:41:46","leaseExpires":"09/25/2020 12:39:54"}]}`),
		}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	leases, err := c.DHCPLeaseList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(leases) != 2 || leases[0].Type != "Reserved" || leases[1].HostName != "" {
		t.Errorf("unexpected leases: %+v", leases)
	}
}

func TestDHCPLeaseRemoveAndConvert(t *testing.T) {
	var gotPaths []string
	ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		if r.FormValue("name") != "lan" || r.FormValue("hardwareAddress") != "00-11-22-33-44-55" {
			t.Errorf("unexpected params: %v", r.PostForm)
		}
		if err := json.NewEncoder(w).Encode(APIResponse{Status: "ok"}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})
	defer ts.Close()

	c, _ := NewClient(ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	ctx := context.Background()
	if err := c.DHCPLeaseRemove(ctx, "lan", "00-11-22-33-44-55"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := c.DHCPLeaseConvertToReserved(ctx, "lan", "00-11-22-33-44-55"); err != nil {
		t.Fatalf("convertToReserved: %v", err)
	}
	if err := c.DHCPLeaseConvertToDynamic(ctx, "lan", "00-11-22-33-44-55"); err != nil {
		t.Fatalf("convertToDynamic: %v", err)
	}
	want := []string{"/api/dhcp/leases/remove", "/api/dhcp/leases/convertToReserved", "/api/dhcp/leases/convertToDynamic"}
	for i, p := range want {
		if gotPaths[i] != p {
			t.Errorf("call %d: got %s, want %s", i, gotPaths[i], p)
		}
	}
}
