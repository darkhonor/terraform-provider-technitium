# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
