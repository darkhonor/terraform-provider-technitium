// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const soaFakeZone = "example.internal"

type zoneSOAFake struct {
	mu           sync.Mutex
	zoneType     string
	scheme       bool
	soaUpdates   int
	createParams url.Values
	failPath     string
	omitScheme   bool
	srv          *httptest.Server
}

func newZoneSOAFake(t *testing.T, zoneType string, scheme bool) *zoneSOAFake {
	t.Helper()
	f := &zoneSOAFake{zoneType: zoneType, scheme: scheme}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == f.failPath {
			_, _ = fmt.Fprint(w, `{"status":"error","errorMessage":"injected failure"}`)
			return
		}
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/api/zones/create":
			f.createParams = r.PostForm
			if r.PostForm.Get("useSoaSerialDateScheme") == "true" && f.zoneType == "Primary" {
				f.scheme = true
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"domain":%q}}`, soaFakeZone)
		case "/api/zones/options/get":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"name":%q,"type":%q,"disabled":false,"dnssecStatus":"Unsigned"}}`, soaFakeZone, f.zoneType)
		case "/api/zones/options/set":
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		case "/api/zones/list":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"zones":[{"name":%q,"soaSerial":7}]}}`, soaFakeZone)
		case "/api/zones/records/get":
			scheme := fmt.Sprintf(`,"useSerialDateScheme":%t`, f.scheme)
			if f.omitScheme {
				scheme = ""
			}
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"records":[{"type":"SOA","ttl":900,"rData":{
				"primaryNameServer":"ns1.example.internal","responsiblePerson":"hostadmin@example.internal",
				"serial":7,"refresh":900,"retry":300,"expire":604800,"minimum":900%s}}]}}`, scheme)
		case "/api/zones/records/update":
			f.soaUpdates++
			f.scheme = r.PostForm.Get("useSerialDateScheme") == "true"
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *zoneSOAFake) resource(t *testing.T) *ZoneResource {
	t.Helper()
	c, err := client.NewClient(client.ClientConfig{BaseURL: f.srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &ZoneResource{client: c}
}

func soaFakeModel(zoneType string, scheme types.Bool) *ZoneResourceModel {
	return &ZoneResourceModel{
		Name:                     types.StringValue(soaFakeZone),
		Type:                     types.StringValue(zoneType),
		SOASerialDateScheme:      scheme,
		Notify:                   types.ListNull(types.StringType),
		AllowTransfer:            types.ListNull(types.StringType),
		ZoneTransferTsigKeyNames: types.ListNull(types.StringType),
		QueryAccess:              types.StringNull(),
		QueryAccessNetworkACL:    types.ListNull(types.StringType),
		DynamicUpdate:            types.StringNull(),
		DynamicUpdateNetworkACL:  types.ListNull(types.StringType),
		SOASerial:                types.Int64Unknown(),
	}
}

func TestReadZoneState_SchemeFromSOA(t *testing.T) {
	for _, zt := range []string{"Primary", "Forwarder"} {
		for _, server := range []bool{true, false} {
			f := newZoneSOAFake(t, zt, server)
			m := soaFakeModel(zt, types.BoolValue(!server))
			if err := f.resource(t).readZoneState(context.Background(), m); err != nil {
				t.Fatalf("%s/%t: readZoneState: %v", zt, server, err)
			}
			if m.SOASerialDateScheme.ValueBool() != server {
				t.Errorf("%s: state = %t, server = %t", zt, m.SOASerialDateScheme.ValueBool(), server)
			}
		}
	}
}

func TestReadZoneState_UnmanagedTypesKeepConfiguredValue(t *testing.T) {
	for _, zt := range []string{"Secondary", "Stub"} {
		f := newZoneSOAFake(t, zt, true)
		r := f.resource(t)

		m := soaFakeModel(zt, types.BoolValue(false))
		if err := r.readZoneState(context.Background(), m); err != nil {
			t.Fatalf("%s: readZoneState: %v", zt, err)
		}
		if m.SOASerialDateScheme.ValueBool() {
			t.Errorf("%s: configured false was overwritten", zt)
		}

		m = soaFakeModel(zt, types.BoolNull())
		if err := r.readZoneState(context.Background(), m); err != nil {
			t.Fatalf("%s: readZoneState: %v", zt, err)
		}
		if !m.SOASerialDateScheme.Equal(types.BoolValue(true)) {
			t.Errorf("%s: null (import) = %v, want true", zt, m.SOASerialDateScheme)
		}
	}
}

func TestReadZoneState_AbsentSchemeFieldKeepsValue(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	f.omitScheme = true
	r := f.resource(t)

	m := soaFakeModel("Primary", types.BoolValue(false))
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if m.SOASerialDateScheme.ValueBool() {
		t.Error("configured false was overwritten")
	}

	m = soaFakeModel("Primary", types.BoolNull())
	if err := r.readZoneState(context.Background(), m); err != nil {
		t.Fatalf("readZoneState: %v", err)
	}
	if !m.SOASerialDateScheme.Equal(types.BoolValue(true)) {
		t.Errorf("null (import) = %v, want true", m.SOASerialDateScheme)
	}
}

func TestReadZoneState_SOAErrorPropagates(t *testing.T) {
	f := newZoneSOAFake(t, "Primary", false)
	f.failPath = "/api/zones/records/get"
	m := soaFakeModel("Primary", types.BoolValue(true))
	if err := f.resource(t).readZoneState(context.Background(), m); err == nil {
		t.Fatal("expected error when the SOA read fails")
	}
}
