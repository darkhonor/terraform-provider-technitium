# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Tested against Technitium DNS Server 15.5.1. The **Breaking** items below can stop an existing
configuration from applying; read [Upgrading to v1.3](docs/guides/upgrading-to-v1.3.md) first.

### Added

- `technitium_cluster`, `technitium_cluster_secondary`, `technitium_sso`, `technitium_user`, and
  `technitium_api_token` resources. Contributed by [@Ujstor](https://github.com/Ujstor). ([#94])
- DHCP management: `technitium_dhcp_scope` and `technitium_dhcp_reserved_lease` resources, and
  `technitium_dhcp_scope`, `technitium_dhcp_scopes`, and `technitium_dhcp_leases` data sources.
  Contributed by [@dustins](https://github.com/dustins), based on work by
  [@bartei](https://github.com/bartei). ([#150])
- `technitium_zone`: `query_access`, `dynamic_update`, and their network ACLs. ([#89])
- `technitium_zone`: `dnssec.change_acknowledgment`, in-place NSEC/NSEC3 conversion, and
  plan-time validation of `algorithm` and `curve`. ([#96])
- `technitium_record`: `comments` attribute. Contributed by
  [@pushkar-anand](https://github.com/pushkar-anand). ([#139], [#140])
- `technitium_server_settings`: web service TLS settings. ([#94])
- `legacy_token_auth` provider argument (`TECHNITIUM_LEGACY_TOKEN_AUTH`) for servers older than
  15.0. Contributed by [@bytestrom](https://github.com/bytestrom). (GHSA-27mx-6hfq-f887, [#121])
- `AUTHORS` file and an Attribution section in `CONTRIBUTING.md`. ([#115])
- TLS acceptance-test environment. ([#94])

### Changed

- **Breaking:** the API token is sent as an `Authorization: Bearer` header. Servers older than
  15.0 need `legacy_token_auth = true`. Contributed by [@bytestrom](https://github.com/bytestrom).
  (GHSA-27mx-6hfq-f887, [#121])
- **Breaking:** two `FWD` records in one zone with the same `value` and `protocol` are refused.
  ([#141])
- **Breaking:** redirects are followed only within the same scheme, host, and port; `server_url`
  and `node_url` must name the final address. Writes are sent as `POST` form bodies, so a proxy
  must allow `POST` on `/api/*`. See [Reverse Proxies and Load
  Balancers](docs/guides/reverse-proxy.md). ([#147], [#124])
- **Breaking:** under `strict` STIG enforcement (the default), unsigning a zone requires
  `change_acknowledgment = "unsigned"`. Unsigning now warns in every posture. ([#96])
- In-place DNSSEC `algorithm`/`curve` changes are refused unless acknowledged. ([#96])
- Forwarder zones, and Primary zones whose server value differs from the configuration, show a
  one-time `soa_serial_date_scheme` change after upgrading; applying it increments the serial.
  ([#135])
- Building from source requires Go 1.27.1. ([#126])

### Fixed

- `technitium_server_settings`: `forwarders` no longer fail with "inconsistent result after
  apply"; forms the server would rewrite are rejected at plan time. ([#134])
- `technitium_zone`: `soa_serial_date_scheme` is read from the SOA record and applied on update.
  ([#135])
- `technitium_zone`: a failure after zone creation leaves the zone tainted in state instead of
  orphaned. ([#135])
- `technitium_zone`: DNSSEC parameter changes on a signed ECDSA/EdDSA zone are no longer
  silently ignored (RSA: [#101]). ([#96])
- `technitium_zone`: a `dnssec` block on a non-Primary zone is refused at plan time. ([#100])
- `technitium_record`: refresh no longer fails when the parent zone is gone. ([#88])
- `technitium_record`: updates no longer erase the record's comment. Contributed by
  [@pushkar-anand](https://github.com/pushkar-anand). ([#139], [#140])
- `technitium_sso` and `technitium_user`: removing an attribute now clears it on the server, and
  server-side SSO `group_map` entries show as drift. ([#94])
- `technitium_blocked_zones` / `technitium_allowed_zones` data sources: error responses are no
  longer returned as domain lists. ([#123])
- The `technitium_catalog_membership` example no longer declares `dnssec` on a Catalog zone.
  ([#116])
- An uppercase `HTTPS://` `server_url` now gets the configured TLS settings. ([#147])
- `make docs` and `make generate` work from any directory, including worktrees. ([#114])

### Security

- The API token is no longer sent in request URLs. Reported and fixed by
  [@bytestrom](https://github.com/bytestrom). (GHSA-27mx-6hfq-f887, [#121])
- Writes are sent as `POST` form bodies, keeping record values, comments, and `proxy_password` out
  of URLs and access logs. ([#147])
- Redirects to another scheme, host, or port are refused, so credentials cannot follow them.
  ([#147], [#124])
- Credentials are redacted from errors and diagnostics. (GHSA-27mx-6hfq-f887, [#147])
- `FWD` record pairs that Technitium cannot tell apart are refused, preventing silent loss of
  the DNSSEC-validating forwarder. ([#141])
- Every Go source file carries copyright and SPDX headers. ([#115])
- The hardcoded fallback API token is removed from the acceptance suite. ([#108])
- Go 1.26.6 toolchain to clear a govulncheck finding. ([#103])

### Documentation

- New guides: Upgrading to v1.3 and Reverse Proxies and Load Balancers. ([#149], [#153])
- README: Technitium requirement raised to 15.0 (15.5.1 recommended). ([#149])
- DNSSEC examples on `technitium_zone`, a `technitium_catalog_membership` template, and default
  page titles. ([#116])
- Vendored Technitium API docs removed in favor of upstream links. ([#152])

### Test infrastructure

- Acceptance configurations follow `TECHNITIUM_SERVER_URL` and `TECHNITIUM_CACERT`. ([#115])
- Live-server setup is gated behind `TF_ACC`. ([#109])
- The direct test client follows the suite's transport. ([#111])

### Dependencies

- chore(deps): update actions/checkout action to v7.0.1 ([#86])
- chore(deps): update ossf/scorecard-action action to v2.4.4 ([#87])
- chore(deps): update github/codeql-action action to v4.37.4 ([#91])
- chore(deps): update github/codeql-action action to v4.37.6 ([#92])
- chore(deps): update actions/attest-build-provenance action to v4.2.2 ([#93])
- chore(deps): update github/codeql-action action to v4.37.7 ([#95])
- chore(deps): upgrade Go toolchain and CI to 1.27.1 ([#126])
- chore(deps): update github/codeql-action action to v4.37.9 ([#127])
- chore(deps): Bump google.golang.org/grpc from 1.82.1 to 1.83.2 in the go_modules group across 1 directory ([#128])
- chore(deps): update github/codeql-action action to v4.38.0 ([#131])
- fix(ci): update govulncheck for Go 1.27 compatibility ([#132])
- chore(deps): update technitium/dns-server:latest docker digest to b8efe03 ([#133])
- chore(deps): update github/codeql-action action to v4.38.2 ([#137])
- fix(deps): update module github.com/hashicorp/go-uuid to v1.0.4 ([#138])

## [1.2.1] - 2026-07-26

### Added

- Forwarder (`FWD`) record support is now usable end to end. Forwarder zones are
  created empty (`initializeForwarder=false`), so each upstream forwarder is
  managed as its own `technitium_record` resource rather than being baked into
  zone creation. Previously `technitium_zone` with `type = "Forwarder"` failed
  with `Parameter 'forwarder' missing.` and there was no `forwarder` argument to
  supply. Documentation gains three worked examples — a single forwarder, a
  DNSSEC-validating DoT forwarder with a plain fallback, and conditional
  forwarding for an internal namespace — each covered by acceptance tests.
  ([#69], closes [#75])

### Changed

- `FWD` record identity now includes `dnssec_validation`. Import IDs use
  `zone::name::FWD::forwarder:protocol:priority:dnssecValidation`, which lets two
  otherwise-identical forwarders be told apart in Terraform state. The legacy
  three-field form `forwarder:protocol:priority` is still accepted on import and
  leaves `dnssec_validation` unset rather than fabricating a value. ([#69])
- **`dnssec_validation` now forces replacement.** Changing it destroys and
  recreates the record instead of updating in place. This is deliberate: the
  Technitium update API treats `dnssecValidation` as a settable value rather than
  an identifier and provides no `newDnssecValidation`, so an in-place update of
  one of two colliding forwarders rewrites it onto the other and the two collapse
  into a single record. See **Upgrade Notes**. ([#69])

### Fixed

- `FWD` import no longer writes the CAA tag into the `protocol` attribute. The
  import parser returned a single shared string slot that CAA used for its tag
  and FWD reused for its protocol; `ImportState` read it under the CAA name and
  assigned it to `protocol`. Correct only by coincidence of the two types sharing
  a slot. ([#69])
- An unrelated update to a `FWD` record no longer silently disables DNSSEC
  validation. `dnssecValidation` is omitted from a partial update request when the
  configuration does not set it, and Technitium treats a missing value as `false`
  rather than "leave unchanged" — so a TTL-only change turned validation off. The
  provider now always sends the current value. ([#69])
- `FWD` records that omit `dnssec_validation` no longer show a permanent diff.
  Refresh adopted the server's value into state, producing a `false -> null`
  change on every plan, which combined with the new replacement semantics marked
  untouched records for destruction. Refresh now updates the attribute only when
  it is already tracked. ([#69])
- Compliance requirements re-validated against the July 2026 DNS STIG releases —
  BIND 9.x V3R3 and Windows Server 2022 DNS V2R5, both published 2026-07-01.
  Neither adds or removes rules, and all 42 STIG rules this provider cites are
  unchanged, so no requirement needed revision. Version citations updated
  accordingly. ([#83])
- CI: action pin check made deterministic. ([#63])

### Security

- fix(deps): bump golang.org/x/text to v0.39.0 (GO-2026-5970) ([#80])
- fix(deps): bump google.golang.org/grpc to v1.82.1 (GHSA-hrxh-6v49-42gf) ([#81])

### Dependencies

- chore(deps): update github/codeql-action action to v4.36.0 ([#64])
- chore(deps): update actions/checkout action to v6.0.3 ([#65])
- chore(deps): update github/codeql-action action to v4.36.1 ([#66])
- chore(deps): update github/codeql-action action to v4.36.2 ([#67])
- fix(deps): update module software.sslmate.com/src/go-pkcs12 to v0.7.2 ([#68])
- chore(deps): update actions/checkout action to v7 ([#70])
- fix(deps): update module software.sslmate.com/src/go-pkcs12 to v0.7.3 ([#71])
- chore(deps): update actions/setup-go action to v6.5.0 ([#72])
- chore(deps): update actions/attest-build-provenance action to v4.1.1 ([#74])
- chore(deps): update goreleaser/goreleaser-action action to v7.2.3 ([#76])
- chore(deps): update github/codeql-action action to v4.37.3 ([#77])
- chore(deps): update actions/setup-go action to v7 ([#79])
- chore(deps): update technitium/dns-server:latest docker digest to 3580381 —
  moves the acceptance-test fixture from Technitium **15.2 to 15.4** ([#73])
- chore(renovate): drop the release-age delay on container images ([#82])

### Upgrade Notes

**`dnssec_validation` changes now replace the record.** If your configuration
changes that attribute on an existing `FWD` record, the next plan shows a
destroy-and-create rather than an in-place update. The record is briefly absent
during apply. This is the safe behaviour — the in-place path it replaces could
silently merge two forwarders into one.

**Do not define two `FWD` records that differ only by `dnssec_validation`.** If
two share the same `value`, `protocol` and `forwarder_priority`, the Technitium
API cannot tell them apart: a delete removes whichever was created first and an
update collapses the pair, both reporting success. Give each forwarder a distinct
`forwarder_priority` (or a different `value` or `protocol`). Verified against
Technitium 15.2 and 15.4 and reported upstream as
[TechnitiumSoftware/DnsServer#2069](https://github.com/TechnitiumSoftware/DnsServer/issues/2069).
The provider contains what it can — replacement semantics avoid the merging
update path — but it cannot address one of an existing colliding pair.

## [1.2.0] - 2026-05-24

### Added

- New `technitium_catalog_membership` resource manages catalog zone membership
  (RFC 9432) declaratively for Primary, Secondary, Stub, and Forwarder zones.
  Plan-time validation against the live Technitium API verifies that both the
  member zone and the catalog zone exist and that the catalog zone is of type
  Catalog or SecondaryCatalog. Destroying the resource unsets membership
  without deleting the underlying zone. ([#23])
- New `Client.ZoneSetCatalog(ctx, zone, catalog)` API client helper. Passing
  an empty catalog string unsets membership.

### Fixed

- STIG validators DNS-REQ-004 (zone-transfer ACL) and DNS-REQ-016 (notify
  addresses) now correctly enforce against `technitium_zone` resources.
  Both validators were silently no-op in v1.0.x and v1.1.x due to a schema
  alignment defect; strict-mode users running existing HCL without
  `allow_transfer` or `notify` populated will now see findings on
  `terraform plan`. See **Upgrade Notes** below for remediation paths.
  ([#39])

### Security

- Acceptance-test token provisioning no longer exposes the Technitium admin
  password or per-run API session token via `/proc/PID/cmdline` (`ps -ef`) or
  `/proc/PID/environ` (`ps eww`). The `testacc-token`, `testacc-token-tls`,
  and `testacc-up-tls` readiness-probe recipes were rewritten to pipe the
  password to a new `scripts/test-token-bootstrap.sh` helper on stdin. The
  helper reads the credential from stdin into a local shell variable,
  URL-encodes it via a python helper that also reads from stdin, and sends
  the form body to curl via `--data @-` on a bash heredoc. The password
  value therefore never enters argv or env of any process in the test
  harness flow. No production code or wire shape changes. ([#35])
- New CI gate (`Verify action SHA pins`) enforces full 40-character commit
  SHA pinning on every GitHub Actions `uses:` reference via
  `suzuki-shunsuke/pinact-action`. The enforcement action itself is also
  SHA-pinned so the gate does not introduce a new mutable workflow
  dependency. Policy documented in [.github/SECURITY.md](.github/SECURITY.md).
  Renovate manages SHA bumps for the `github-actions` ecosystem with a
  three-day soak window. ([#56])
- Bumped `golang.org/x/net`, `golang.org/x/crypto`, and the Go toolchain
  to clear GO-2026-5026 and GO-2026-5013 advisories. ([#41])

### Test infrastructure

- The Technitium test container now runs as the host user instead of root.
  Bind-mounted test data is created with host ownership at the make-target
  layer, eliminating the need for `sudo rm -rf` cleanup after a test run.
  CI runners (GitHub Actions UID 1001) pick up their own UID via
  `HOST_UID` / `HOST_GID` exported from `GNUmakefile`. ([#36])
- In-process TLS fixtures unblock NSS-mode and STIG-strict acceptance
  tests that cannot run under HTTP. The `testacc-up-tls` target generates
  a fresh self-signed CA + server cert under `./testdata/tls/`, brings up
  a Technitium container with HTTPS on port 5443, and runs the full
  acceptance suite over TLS. ([#33])

### Documentation

- DISA STIG library pins refreshed from V3R1 → V3R2 (BIND 9.x) and
  V2R3 → V2R4 (Windows Server 2022 DNS). Both released
  2026-04-01 per the [DISA STIG Public Library](https://public.cyber.mil/stigs/downloads/).
  Zero validator-code impact: none of the provider's 28 DNS-REQ validators
  cite any of the five rules that changed across both refreshed STIGs.
  Provenance analysis posted as a comment on [#53]. ([#53])
- README expanded with "Why use Terraform with Technitium?" sections for
  already-IaC, new-to-IaC, and multi-Technitium audiences. Quick Start
  split into "Homelab quick start" (HTTP, warn-mode STIG) and "Production
  / hardened deployment" (HTTPS, custom CA, strict mode, full DNSSEC).
  Capability comparison vs. the generic `hashicorp/dns` provider added,
  with an explicit "where `hashicorp/dns` is the better fit" callout for
  AD-integrated / Kerberos environments.
- New community-health files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
  (Contributor Covenant 2.1), GitHub Forms issue templates (bug,
  enhancement), `.github/ISSUE_TEMPLATE/config.yml` routing security
  reports to the private GitHub Security Advisory flow, and a
  `.github/pull_request_template.md`. ([#60])

### Known limitations

- The three Technitium per-member catalog override flags
  (`overrideCatalogQueryAccess`, `overrideCatalogZoneTransfer`,
  `overrideCatalogNotify`) are not yet exposed. Until they are, settings
  inherited from the catalog zone (queryAccess, zoneTransfer, notify) take
  precedence over any matching settings declared on the member zone via
  `technitium_zone`. The `technitium_catalog_membership` resource emits a
  plan-time warning whenever it is created or updated. Tracked in [#29].
- Catalog-driven zone provisioning to secondary name servers is not exercised
  by the current acceptance suite (single-node test container). Tracked in
  [#30].

### Upgrade Notes

**For strict-mode STIG users upgrading from v1.0.x or v1.1.x:** the
`DNS-REQ-004` and `DNS-REQ-016` STIG validators were silently no-op in
prior releases and now properly enforce. If your existing HCL leaves
`allow_transfer` or `notify` unset on Primary zones, `terraform plan`
will now surface STIG findings under strict mode. Three remediation
paths cover every supported topology:

**DNS-REQ-004 — zone-transfer ACL (NIST AC-3, AC-4):**

```hcl
resource "technitium_zone" "primary_with_secondaries" {
  name = "example.com"
  type = "Primary"

  # Production / hardened: enumerate the secondary nameserver IPs that
  # are authorized to pull zone data via AXFR / IXFR.
  allow_transfer = ["192.0.2.10", "192.0.2.11"]
}

resource "technitium_zone" "primary_no_transfers" {
  name = "internal.example.com"
  type = "Primary"

  # Hidden-primary or single-server topologies: deny transfers entirely.
  # Setting to [] is explicit and satisfies the validator.
  allow_transfer = []
}
```

**DNS-REQ-016 — notify addresses (NIST SC-8, CM-6):**

```hcl
resource "technitium_zone" "primary_with_secondaries" {
  name = "example.com"
  type = "Primary"

  # Production / hardened: list the secondary nameservers that should
  # receive NOTIFY messages when this zone's SOA serial advances.
  notify = ["192.0.2.10", "192.0.2.11"]
}

resource "technitium_zone" "primary_silent" {
  name = "internal.example.com"
  type = "Primary"

  # Hidden-primary topology: suppress NOTIFY entirely. The validator
  # accepts an explicit empty list as a documented intentional choice.
  notify = []
}
```

**If you are not yet ready to populate these fields**, set
`stig_compliance.enforcement = "warn"` in the provider block to demote
the new findings from blocking errors to plan-time warnings while you
work through your zones. `"silent"` suppresses them entirely. Both
settings preserve the validator coverage for future runs.

[#140]: https://github.com/darkhonor/terraform-provider-technitium/issues/140
[#121]: https://github.com/darkhonor/terraform-provider-technitium/issues/121
[#88]: https://github.com/darkhonor/terraform-provider-technitium/issues/88
[#89]: https://github.com/darkhonor/terraform-provider-technitium/issues/89
[#94]: https://github.com/darkhonor/terraform-provider-technitium/issues/94
[#96]: https://github.com/darkhonor/terraform-provider-technitium/issues/96
[#100]: https://github.com/darkhonor/terraform-provider-technitium/issues/100
[#101]: https://github.com/darkhonor/terraform-provider-technitium/issues/101
[#108]: https://github.com/darkhonor/terraform-provider-technitium/issues/108
[#114]: https://github.com/darkhonor/terraform-provider-technitium/issues/114
[#115]: https://github.com/darkhonor/terraform-provider-technitium/issues/115
[#116]: https://github.com/darkhonor/terraform-provider-technitium/issues/116
[#123]: https://github.com/darkhonor/terraform-provider-technitium/issues/123
[#124]: https://github.com/darkhonor/terraform-provider-technitium/issues/124
[#126]: https://github.com/darkhonor/terraform-provider-technitium/issues/126
[#127]: https://github.com/darkhonor/terraform-provider-technitium/issues/127
[#128]: https://github.com/darkhonor/terraform-provider-technitium/issues/128
[#131]: https://github.com/darkhonor/terraform-provider-technitium/issues/131
[#132]: https://github.com/darkhonor/terraform-provider-technitium/issues/132
[#133]: https://github.com/darkhonor/terraform-provider-technitium/issues/133
[#134]: https://github.com/darkhonor/terraform-provider-technitium/issues/134
[#135]: https://github.com/darkhonor/terraform-provider-technitium/issues/135
[#137]: https://github.com/darkhonor/terraform-provider-technitium/issues/137
[#138]: https://github.com/darkhonor/terraform-provider-technitium/issues/138
[#139]: https://github.com/darkhonor/terraform-provider-technitium/issues/139
[#141]: https://github.com/darkhonor/terraform-provider-technitium/issues/141
[#147]: https://github.com/darkhonor/terraform-provider-technitium/issues/147
[#149]: https://github.com/darkhonor/terraform-provider-technitium/issues/149
[#150]: https://github.com/darkhonor/terraform-provider-technitium/issues/150
[#152]: https://github.com/darkhonor/terraform-provider-technitium/issues/152
[#153]: https://github.com/darkhonor/terraform-provider-technitium/issues/153
[#23]: https://github.com/darkhonor/terraform-provider-technitium/issues/23
[#29]: https://github.com/darkhonor/terraform-provider-technitium/issues/29
[#30]: https://github.com/darkhonor/terraform-provider-technitium/issues/30
[#33]: https://github.com/darkhonor/terraform-provider-technitium/issues/33
[#35]: https://github.com/darkhonor/terraform-provider-technitium/issues/35
[#36]: https://github.com/darkhonor/terraform-provider-technitium/issues/36
[#39]: https://github.com/darkhonor/terraform-provider-technitium/pull/39
[#41]: https://github.com/darkhonor/terraform-provider-technitium/pull/41
[#53]: https://github.com/darkhonor/terraform-provider-technitium/issues/53
[#56]: https://github.com/darkhonor/terraform-provider-technitium/issues/56
[#60]: https://github.com/darkhonor/terraform-provider-technitium/issues/60

## [1.1.0] - 2026-03-29

### Breaking Changes

- **Record ID format changed** from `zone/name/type` to `zone::name::type::value`. This affects
  all `technitium_record` resources in state and the `terraform import` format. No state migration
  is provided — re-import any existing records using the new format. ([#18])
- **Import format changed** for all record types:
  - Simple types: `zone::name::type::value`
  - MX: `zone::name::MX::exchange:priority`
  - SRV: `zone::name::SRV::target:priority:weight:port`
  - CAA: `zone::name::CAA::value:flags:tag`

### Added

- Multi-record support: multiple DNS records at the same name and type are now fully managed
  without ID collisions (e.g., round-robin A records, multiple MX records). Set `overwrite = false`
  on each resource. ([#18])
- Type-aware record matching for MX (exchange + priority), SRV (target + priority + weight + port),
  and CAA (value + flags + tag) ensures each record is uniquely identified. ([#18])
- 11 new acceptance tests covering multi-record collision, SRV edge cases, TXT torture tests
  (special characters, long DKIM keys), and lifecycle scenarios (destroy-one-of-two, import
  with siblings). ([#18])
- `.golangci.yml` configuration with 17 linters enabled for security, nil-safety, error handling,
  and code correctness. ([#20])
- `context.Context` propagated through all HTTP client methods, enabling request cancellation
  and timeout propagation from Terraform Plugin Framework. ([#22])
- Scorecard workflow hardening and fuzz tests. ([#11])
- Declarative STIG test suite with schema-aware integration tests. ([#10])

### Fixed

- Record ID collision when multiple records share the same name and type — the original bug
  that caused infinite drift loops and delete failures. ([#6], [#18])
- STIG engine now flags omitted attributes as non-compliant findings instead of silently
  passing (default-allow bug). ([#9], [#10])
- `errcheck` findings: unchecked `resp.Body.Close()` and `f.Close()` return values. ([#19])
- `staticcheck` finding: De Morgan's law applied to NSS categorization check. ([#19])
- `rangeValCopy` in STIG engine: eliminated 128-byte copy per iteration. ([#20])
- `noctx` findings: HTTP calls now use `http.NewRequestWithContext` instead of
  `http.Client.Get`/`PostForm`. ([#22])

### Changed

- Migrated golangci-lint from v1.64.8 to v2.11.4. ([#12], [#19])
- Import state now defaults `overwrite` to `false` (previously `true`). ([#18])
- Record `id` schema attribute no longer uses `UseStateForUnknown` plan modifier since the ID
  changes when the record value changes. ([#18])

### Dependencies

- `actions/checkout` 4.3.1 → 6.0.2 ([#13])
- `actions/setup-go` 5.6.0 → 6.3.0 ([#17])
- `actions/upload-artifact` 6.0.0 → 7.0.0 ([#14])
- `actions/attest-build-provenance` updated ([#16])
- `crazy-max/ghaction-import-gpg` 6.3.0 → 7.0.0 ([#15])

## [1.0.1] - 2026-03-23

### Fixed

- STIG engine treats omitted attributes as non-compliant findings. ([#9])

## [1.0.0] - 2026-03-19

### Added

- Initial release of the Technitium DNS Terraform provider.
- DNS zone management (Primary, Secondary, Stub, Forwarder) with DNSSEC signing support.
- DNS record management for A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA record types.
- TSIG key management for authenticated zone transfers.
- Server-wide DNS settings resource and data source.
- Domain blocking and allowing resources.
- Built-in DISA STIG compliance validation with 28 DNS security requirements.
- NIST SP 800-53 Rev. 5 control traceability and baseline categorization.
- NSS/CNSSI 1253 support for classified environments.
- TLS configuration with custom CA support and environment variable fallbacks.
- Client-side DNS record input validation.
- FIPS 140-2 build support via BoringCrypto.
- OSSF Scorecard, CodeQL, and Dependabot integration.

[1.2.1]: https://github.com/darkhonor/terraform-provider-technitium/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/darkhonor/terraform-provider-technitium/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/darkhonor/terraform-provider-technitium/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/darkhonor/terraform-provider-technitium/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/darkhonor/terraform-provider-technitium/releases/tag/v1.0.0
[#6]: https://github.com/darkhonor/terraform-provider-technitium/issues/6
[#9]: https://github.com/darkhonor/terraform-provider-technitium/issues/9
[#10]: https://github.com/darkhonor/terraform-provider-technitium/pull/10
[#11]: https://github.com/darkhonor/terraform-provider-technitium/pull/11
[#12]: https://github.com/darkhonor/terraform-provider-technitium/issues/12
[#13]: https://github.com/darkhonor/terraform-provider-technitium/pull/13
[#14]: https://github.com/darkhonor/terraform-provider-technitium/pull/14
[#15]: https://github.com/darkhonor/terraform-provider-technitium/pull/15
[#16]: https://github.com/darkhonor/terraform-provider-technitium/pull/16
[#17]: https://github.com/darkhonor/terraform-provider-technitium/pull/17
[#18]: https://github.com/darkhonor/terraform-provider-technitium/pull/18
[#19]: https://github.com/darkhonor/terraform-provider-technitium/pull/19
[#20]: https://github.com/darkhonor/terraform-provider-technitium/pull/20
[#22]: https://github.com/darkhonor/terraform-provider-technitium/pull/22
[#63]: https://github.com/darkhonor/terraform-provider-technitium/pull/63
[#64]: https://github.com/darkhonor/terraform-provider-technitium/pull/64
[#65]: https://github.com/darkhonor/terraform-provider-technitium/pull/65
[#66]: https://github.com/darkhonor/terraform-provider-technitium/pull/66
[#67]: https://github.com/darkhonor/terraform-provider-technitium/pull/67
[#68]: https://github.com/darkhonor/terraform-provider-technitium/pull/68
[#69]: https://github.com/darkhonor/terraform-provider-technitium/pull/69
[#70]: https://github.com/darkhonor/terraform-provider-technitium/pull/70
[#71]: https://github.com/darkhonor/terraform-provider-technitium/pull/71
[#72]: https://github.com/darkhonor/terraform-provider-technitium/pull/72
[#73]: https://github.com/darkhonor/terraform-provider-technitium/pull/73
[#74]: https://github.com/darkhonor/terraform-provider-technitium/pull/74
[#75]: https://github.com/darkhonor/terraform-provider-technitium/issues/75
[#76]: https://github.com/darkhonor/terraform-provider-technitium/pull/76
[#77]: https://github.com/darkhonor/terraform-provider-technitium/pull/77
[#79]: https://github.com/darkhonor/terraform-provider-technitium/pull/79
[#80]: https://github.com/darkhonor/terraform-provider-technitium/pull/80
[#81]: https://github.com/darkhonor/terraform-provider-technitium/pull/81
[#82]: https://github.com/darkhonor/terraform-provider-technitium/pull/82
[#83]: https://github.com/darkhonor/terraform-provider-technitium/pull/83
[#86]: https://github.com/darkhonor/terraform-provider-technitium/pull/86
[#87]: https://github.com/darkhonor/terraform-provider-technitium/pull/87
[#91]: https://github.com/darkhonor/terraform-provider-technitium/pull/91
[#92]: https://github.com/darkhonor/terraform-provider-technitium/pull/92
[#93]: https://github.com/darkhonor/terraform-provider-technitium/pull/93
[#95]: https://github.com/darkhonor/terraform-provider-technitium/pull/95
[#103]: https://github.com/darkhonor/terraform-provider-technitium/pull/103
[#109]: https://github.com/darkhonor/terraform-provider-technitium/pull/109
[#111]: https://github.com/darkhonor/terraform-provider-technitium/pull/111
