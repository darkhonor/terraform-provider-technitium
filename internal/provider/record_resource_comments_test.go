// Copyright (c) 2026 Pushkar Anand
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
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// aModel builds the minimum A-record model the param builders and CRUD paths
// need. Every other attribute is left at its zero value, which is null.
func aModel(ip string, ttl int64, comments types.String) *RecordResourceModel {
	return &RecordResourceModel{
		ID:        types.StringValue("comments.example.com::host.comments.example.com::A::" + ip),
		Zone:      types.StringValue("comments.example.com"),
		Name:      types.StringValue("host.comments.example.com"),
		Type:      types.StringValue("A"),
		Value:     types.StringValue(ip),
		TTL:       types.Int64Value(ttl),
		Overwrite: types.BoolValue(false),
		Comments:  comments,
	}
}

func TestBuildAddParams_Comments(t *testing.T) {
	r := &RecordResource{}

	params := r.buildAddParams(aModel("192.0.2.10", 3600, types.StringValue("test note")))
	if got := params["comments"]; got != "test note" {
		t.Errorf("comments = %q, want %q", got, "test note")
	}

	for name, v := range map[string]types.String{"null": types.StringNull(), "unknown": types.StringUnknown()} {
		params := r.buildAddParams(aModel("192.0.2.10", 3600, v))
		if got, present := params["comments"]; present {
			t.Errorf("%s comments: parameter sent as %q, want it omitted", name, got)
		}
	}
}

// An empty string must be SENT on update, not dropped: it is the only way a
// comment cleared in configuration reaches the server.
func TestBuildUpdateParams_CommentsIncludingEmpty(t *testing.T) {
	r := &RecordResource{}
	state := aModel("192.0.2.10", 3600, types.StringValue("old note"))

	for _, want := range []string{"new note", ""} {
		params := r.buildUpdateParams(state, aModel("192.0.2.10", 300, types.StringValue(want)))
		got, present := params["comments"]
		if !present {
			t.Fatalf("comments %q: parameter omitted, which clears the comment server-side", want)
		}
		if got != want {
			t.Errorf("comments = %q, want %q", got, want)
		}
	}

	// Unknown is left to Update, which reads the server's value first.
	params := r.buildUpdateParams(state, aModel("192.0.2.10", 300, types.StringUnknown()))
	if got, present := params["comments"]; present {
		t.Errorf("unknown comments: builder sent %q, want it left to Update", got)
	}
}

// fakeRecordServer serves one A record and records the query of every
// records/update call, so a test can assert what an update actually sent.
type fakeRecordServer struct {
	mu       sync.Mutex
	comments string
	ttl      int
	updates  []url.Values
}

func (f *fakeRecordServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch req.URL.Path {
		case "/api/zones/records/get":
			_, _ = fmt.Fprintf(w, `{"status":"ok","response":{"zone":{},"records":[{
				"name":"host.comments.example.com","type":"A","ttl":%d,"disabled":false,
				"rData":{"ipAddress":"192.0.2.10"},"lastModified":"2026-01-01T00:00:00Z",
				"comments":%q}]}}`, f.ttl, f.comments)
		case "/api/zones/records/update":
			q := req.URL.Query()
			f.updates = append(f.updates, q)
			// Mirror Technitium: the parameter is assigned unconditionally.
			f.comments = q.Get("comments")
			_, _ = fmt.Sscanf(q.Get("ttl"), "%d", &f.ttl)
			_, _ = fmt.Fprint(w, `{"status":"ok","response":{}}`)
		default:
			t.Errorf("unexpected request path: %s", req.URL.Path)
		}
	}
}

func runRecordUpdate(t *testing.T, srv *fakeRecordServer, state, plan *RecordResourceModel) *RecordResourceModel {
	t.Helper()
	ts := httptest.NewServer(srv.handler(t))
	t.Cleanup(ts.Close)

	c, err := client.NewClient(client.ClientConfig{BaseURL: ts.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	r := &RecordResource{client: c}

	schemaResp := fwresource.SchemaResponse{}
	r.Schema(context.Background(), fwresource.SchemaRequest{}, &schemaResp)

	tfPlan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := tfPlan.Set(context.Background(), plan); diags.HasError() {
		t.Fatalf("plan.Set: %v", diags)
	}
	tfState := tfsdk.State{Schema: schemaResp.Schema}
	if diags := tfState.Set(context.Background(), state); diags.HasError() {
		t.Fatalf("state.Set: %v", diags)
	}

	req := fwresource.UpdateRequest{Plan: tfPlan, State: tfState}
	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Update(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}

	var saved RecordResourceModel
	if diags := resp.State.Get(context.Background(), &saved); diags.HasError() {
		t.Fatalf("state.Get: %v", diags)
	}
	return &saved
}

// The regression: a TTL-only update of a record whose comment Terraform does
// not know (state from before this attribute existed, refreshed with
// -refresh=false) must carry the server's comment through, not erase it.
func TestRecordUpdate_UnknownCommentsPreservesServerValue(t *testing.T) {
	srv := &fakeRecordServer{comments: "test note", ttl: 3600}

	saved := runRecordUpdate(t, srv,
		aModel("192.0.2.10", 3600, types.StringNull()),
		aModel("192.0.2.10", 300, types.StringUnknown()))

	if len(srv.updates) != 1 {
		t.Fatalf("records/update called %d times, want 1", len(srv.updates))
	}
	if got := srv.updates[0].Get("comments"); got != "test note" {
		t.Errorf("update sent comments=%q, want the server's %q", got, "test note")
	}
	if srv.comments != "test note" {
		t.Errorf("server comment after update = %q, want it preserved", srv.comments)
	}
	if got := saved.Comments.ValueString(); got != "test note" {
		t.Errorf("state comments = %q, want %q", got, "test note")
	}
}

func TestRecordUpdate_KnownCommentsAreSent(t *testing.T) {
	for _, want := range []string{"new note", ""} {
		srv := &fakeRecordServer{comments: "old note", ttl: 3600}

		saved := runRecordUpdate(t, srv,
			aModel("192.0.2.10", 3600, types.StringValue("old note")),
			aModel("192.0.2.10", 3600, types.StringValue(want)))

		if srv.comments != want {
			t.Errorf("server comment = %q, want %q", srv.comments, want)
		}
		if got := saved.Comments.ValueString(); got != want {
			t.Errorf("state comments = %q, want %q", got, want)
		}
	}
}

// TestAccRecordResource_Comments covers the comments lifecycle against a live
// server, including the regression from issue #139: a comment set outside
// Terraform must survive an unrelated in-place update of a record whose
// configuration does not mention comments.
func TestAccRecordResource_Comments(t *testing.T) {
	const (
		zone = "rec-comments-test.example.com"
		name = "www.rec-comments-test.example.com"
		addr = "technitium_record.web"
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with a comment.
			{
				Config: testAccRecordAComments(zone, name, 3600, `"first note"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "comments", "first note"),
					checkRecordCommentFn(t, zone, name, "first note"),
				),
			},
			// Change the comment.
			{
				Config: testAccRecordAComments(zone, name, 3600, `"second note"`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "comments", "second note"),
					checkRecordCommentFn(t, zone, name, "second note"),
				),
			},
			// Stop managing it: omitting the attribute keeps the comment, even
			// across an in-place update.
			{
				Config: testAccRecordAComments(zone, name, 300, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "ttl", "300"),
					resource.TestCheckResourceAttr(addr, "comments", "second note"),
					checkRecordCommentFn(t, zone, name, "second note"),
				),
			},
			// Issue #139: a comment written outside Terraform survives a
			// TTL-only update when the configuration omits comments.
			{
				PreConfig: func() {
					c := testAccDirectClient(t)
					err := c.RecordUpdate(context.Background(), name, zone, "A", 300, map[string]string{
						"ipAddress": "192.0.2.10",
						"comments":  "set in console",
					})
					if err != nil {
						t.Fatalf("out-of-band comment update failed: %s", err)
					}
				},
				Config: testAccRecordAComments(zone, name, 600, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "ttl", "600"),
					resource.TestCheckResourceAttr(addr, "comments", "set in console"),
					checkRecordCommentFn(t, zone, name, "set in console"),
				),
			},
			// An empty string clears it.
			{
				Config: testAccRecordAComments(zone, name, 600, `""`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(addr, "comments", ""),
					checkRecordCommentFn(t, zone, name, ""),
				),
			},
			// Import reads the comment back.
			{
				ResourceName:            addr,
				ImportState:             true,
				ImportStateId:           zone + "::" + name + "::A::192.0.2.10",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"overwrite"},
			},
		},
	})
}

// testAccRecordAComments renders an A record whose comments line is omitted
// when comments is "" and otherwise written verbatim (pass a quoted HCL string).
func testAccRecordAComments(zone, name string, ttl int, comments string) string {
	commentsLine := ""
	if comments != "" {
		commentsLine = "comments = " + comments
	}
	return testAccProviderHCL() + fmt.Sprintf(`

resource "technitium_zone" "test" {
  name = %q
  type = "Primary"
  dnssec { enabled = false }
}

resource "technitium_record" "web" {
  zone      = technitium_zone.test.name
  name      = %q
  type      = "A"
  ttl       = %d
  value     = "192.0.2.10"
  overwrite = false
  %s
}
`, zone, name, ttl, commentsLine)
}

// checkRecordCommentFn asserts the comment the SERVER holds for the A record,
// independently of what the provider wrote to state.
func checkRecordCommentFn(t *testing.T, zone, name, want string) func(*terraform.State) error {
	return func(_ *terraform.State) error {
		records, err := testAccDirectClient(t).RecordGet(context.Background(), name, zone)
		if err != nil {
			return fmt.Errorf("reading %s: %w", name, err)
		}
		for _, rec := range records {
			if rec.Type == "A" {
				if rec.Comments != want {
					return fmt.Errorf("server comment for %s = %q, want %q", name, rec.Comments, want)
				}
				return nil
			}
		}
		return fmt.Errorf("no A record found for %s", name)
	}
}
