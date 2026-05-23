---
subcategory: ""
page_title: "STIG Compliance - Technitium DNS Server Provider"
description: |-
  Built-in DISA STIG compliance validation for Technitium DNS infrastructure managed with Terraform.
---

# STIG Compliance Guide

This provider includes a built-in compliance engine that validates Technitium DNS Server
configuration against security requirements derived from DISA Security Technical
Implementation Guides (STIGs). Compliance findings surface as native Terraform diagnostics
during `terraform validate` and `terraform plan`, giving operators immediate feedback
before any change reaches the DNS infrastructure.

## What Are STIGs?

The Defense Information Systems Agency (DISA) publishes
[Security Technical Implementation Guides (STIGs)](https://www.cyber.mil/stigs) for every
technology component deployed on DoD networks. A STIG is a catalog of security checks --
each one a specific, testable requirement that maps to a higher-level security control.
Compliance with applicable STIGs is mandatory for systems operating under a DoD Authority
to Operate (ATO).

This provider derives its requirements from two STIGs:

| STIG | Version / Release | Library Release Date |
|---|---|---|
| BIND 9.x STIG | V3R2 | 2026-04-01 |
| Windows Server 2022 DNS STIG | V2R4 | 2026-04-01 |

Dates above are the release dates published in the
[DISA STIG Public Library](https://public.cyber.mil/stigs/downloads/) STIG
archive metadata at the time of this provider release. DISA may
announce STIG availability separately (for example via STIG release
notifications) on a different date; the library archive timestamp is
the source-of-record for compliance currency claims in this provider.

## NIST SP 800-53 Controls

[NIST Special Publication 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800-53/r5/upd1/final)
is the federal catalog of security and privacy controls. Each control (e.g., SC-20, AU-12)
describes a security capability that an information system must provide. Controls are
organized into families (AC for Access Control, AU for Audit and Accountability, SC for
System and Communications Protection, and so on) and assigned to baselines (Low, Moderate,
High) based on the potential impact of a loss of confidentiality, integrity, or
availability.

Every requirement in this provider maps to one or more NIST 800-53 controls, providing
direct traceability from a Terraform plan diagnostic to the federal control framework.

## Control Correlation Identifiers (CCIs)

CCIs bridge the gap between STIG rules and NIST 800-53 controls. A single NIST control
may decompose into dozens of CCIs, each representing an atomic, testable statement. When
a STIG rule cites CCI-002418, for example, it is asserting compliance with a specific
aspect of SC-8 (Transmission Confidentiality and Integrity). The provider's requirement
metadata includes CCI mappings so that Risk Management Framework (RMF) evidence packages
can cite the exact CCI satisfied by each Terraform-enforced check.

## How the Provider Uses This

When `stig_compliance.enabled = true`, the provider:

1. Evaluates each resource against applicable DNS-REQ requirements during `terraform validate` (stateless checks) and `terraform plan` (stateful checks).
2. Reports findings as Terraform diagnostics -- errors, warnings, or silent -- depending on the configured enforcement mode.
3. Filters active requirements based on the selected NIST 800-53 baseline (low, moderate, or high).
4. Includes the requirement ID, title, NIST control mapping, and STIG rule provenance in every diagnostic, creating an auditable compliance record directly in your Terraform workflow.

## Quick Start

Enable STIG compliance with a moderate baseline -- the most common starting point for
general-purpose DoD systems:

```hcl
provider "technitium" {
  server_url   = "https://dns.example.com"
  api_token    = var.api_token
  ca_cert_file = var.ca_cert_file

  stig_compliance {
    enabled     = true
    enforcement = "strict"
    categorization {
      baseline = "moderate"
    }
  }
}
```

With this configuration, any resource that violates an applicable DNS-REQ requirement will
produce an error during `terraform plan`, preventing the change from reaching your DNS
server until the violation is resolved.

## Enforcement Modes

The `enforcement` attribute controls how STIG findings are reported. Choose the mode that
matches your operational phase.

### `strict` (default)

STIG findings are reported as **errors** that block `terraform apply`. This is the
recommended mode for production environments and CI/CD pipelines.

```text
$ terraform plan

Planning failed. Terraform encountered errors during planning:

  Error: STIG Violation: DNS-REQ-001 — DNSSEC must be enabled for authoritative zones

    on main.tf line 12, in resource "technitium_zone" "example":
    12:   dnssec = false

  Severity:  HIGH
  Controls:  SC-20, SC-21, SC-23, SC-8, AU-10, CM-6, SI-10
  STIG Rule: BIND-9X-001650

  Authoritative zones must have DNSSEC signing enabled to maintain
  the integrity and authenticity of DNS responses.
```

### `warn`

STIG findings are reported as **warnings** but do not block apply. Use this mode when
migrating existing infrastructure to STIG compliance -- it lets you see all findings
without breaking your workflow.

```text
$ terraform plan

  Warning: STIG Violation: DNS-REQ-001 — DNSSEC must be enabled for authoritative zones

    on main.tf line 12, in resource "technitium_zone" "example":
    12:   dnssec = false

  Severity:  HIGH
  Controls:  SC-20, SC-21, SC-23, SC-8, AU-10, CM-6, SI-10
  STIG Rule: BIND-9X-001650

  Authoritative zones must have DNSSEC signing enabled to maintain
  the integrity and authenticity of DNS responses.

Plan: 1 to add, 0 to change, 0 to destroy.
```

### `silent`

All STIG findings are **suppressed**. No diagnostics are emitted. This mode exists for
development and testing environments where compliance validation is not needed. It is not
recommended for any system that will operate under an ATO.

```text
$ terraform plan

Plan: 1 to add, 0 to change, 0 to destroy.
```

-> **Tip:** Start with `enforcement = "warn"` to audit your existing configuration, then
switch to `strict` once all findings are resolved.

## Baseline Categorization

NIST 800-53 assigns controls to baselines based on the potential impact of a security
breach. The provider uses these baselines to determine which DNS-REQ requirements are
active for your environment.

Setting `baseline = "moderate"` activates all controls assigned to the low and moderate
baselines. Setting `baseline = "high"` activates all controls across all three baselines.

The following table shows which NIST 800-53 controls are included at each baseline level.
This mapping is derived from the `BaselineMembership` data in the provider source code,
which in turn follows NIST SP 800-53B control baseline allocations.

| NIST Control | Low | Moderate | High |
|---|---|---|---|
| SC-20 | Yes | Yes | Yes |
| SC-21 | Yes | Yes | Yes |
| SC-22 | Yes | Yes | Yes |
| SC-5 | Yes | Yes | Yes |
| SC-13 | Yes | Yes | Yes |
| AU-3 | Yes | Yes | Yes |
| AU-9 | Yes | Yes | Yes |
| AU-12 | Yes | Yes | Yes |
| CM-6 | Yes | Yes | Yes |
| IA-5 | Yes | Yes | Yes |
| SC-8 | | Yes | Yes |
| SC-23 | | Yes | Yes |
| IA-3 | | Yes | Yes |
| SI-10 | | Yes | Yes |
| AC-10 | | | Yes |
| SC-24 | | | Yes |
| AU-10 | | | Yes |
| SI-6 | | | Yes |

**Practical impact:** A `low` baseline activates requirements tied to 10 controls. A
`moderate` baseline adds 4 more (SC-8, SC-23, IA-3, SI-10), bringing in requirements
like DNS-REQ-001's full control set, DNS-REQ-002 (TSIG authentication), and DNS-REQ-028
(encrypted management plane). The `high` baseline adds the remaining 4 controls (AC-10,
SC-24, AU-10, SI-6), activating requirements for zone transfer restrictions, query
logging's fail-safe provisions, and dynamic update limits.

## National Security Systems (NSS)

National Security Systems -- systems that process classified information or are critical
to military or intelligence activities -- are governed by
[CNSSI 1253](https://www.cnss.gov/CNSS/issuances/Instructions.cfm)
([full document](https://www.cnss.gov/CNSS/openDoc.cfm?a=6O3JfAcf9xthWGBqw3VCYA%3D%3D&b=C9927DFD7948C56DCEA6C0B7CCD391825E92B1A99EBB83B2BF322F0376107CB05803F18BB7C4B7B61D50EA9045E2AA4B))
rather than the standard NIST 800-53B baselines. CNSSI 1253 requires security
categorization along three independent dimensions: confidentiality, integrity, and
availability. Each dimension is assigned its own impact level (low, moderate, or high),
and the resulting triplet determines the active control set.

### Enabling NSS Mode

Set `nss = true` in the `stig_compliance` block and provide explicit per-objective levels
in the `categorization` block. The shorthand `baseline` attribute is not permitted in NSS
mode -- you must specify all three dimensions.

```hcl
provider "technitium" {
  server_url   = "https://dns.mil.example"
  api_token    = var.api_token
  ca_cert_file = var.ca_cert_file

  stig_compliance {
    enabled     = true
    nss         = true
    enforcement = "strict"
    categorization {
      confidentiality = "high"
      integrity       = "high"
      availability    = "moderate"
    }
  }
}
```

### Dimensional Categorization

When `nss = true`, the provider evaluates each NIST control against the appropriate
dimension. For example:

- **SC-8** (Transmission Confidentiality and Integrity) is evaluated against the
  *confidentiality* dimension. A system categorized as `confidentiality = "moderate"` or
  higher will have SC-8 controls enforced.
- **AU-9** (Protection of Audit Information) is evaluated against the *integrity*
  dimension. A system categorized as `integrity = "low"` or higher will have AU-9
  controls enforced.
- **SC-5** (Denial of Service Protection) is evaluated against the *availability*
  dimension. A system categorized as `availability = "low"` or higher will have SC-5
  controls enforced.

### FIPS Algorithm Restrictions

NSS mode enforces stricter cryptographic algorithm requirements aligned with FIPS 140
validation:

- **TSIG keys** must use `hmac-sha256`, `hmac-sha384`, or `hmac-sha512`. The HMAC-MD5
  and HMAC-SHA1 algorithms are prohibited.
- **DNSSEC signing** with ECDSA requires the P-384 curve (ECDSAP384SHA384). The P-256
  curve (ECDSAP256SHA256) is not permitted in NSS environments because CNSSI 1253
  requires Suite B cryptography at the Top Secret level, which mandates P-384.

These restrictions are enforced regardless of the `enforcement` mode when `nss = true`.
A `technitium_tsig_key` resource configured with `algorithm = "hmac-sha1"` will produce
a hard error even if `enforcement = "warn"`.

### Cross-Resource Enforcement

NSS mode validates compliance across resource boundaries, not just within a single
resource. When a `technitium_zone` references a TSIG key by name for zone transfers, the
provider verifies that the referenced `technitium_tsig_key` resource uses an
NSS-compliant algorithm. This prevents a compliant zone configuration from being
undermined by a non-compliant key.

## Requirement Suppression

Individual requirements can be suppressed by adding their ID to the `suppress` list:

```hcl
provider "technitium" {
  server_url = "https://dns.example.com"
  api_token  = var.api_token

  stig_compliance {
    enabled     = true
    enforcement = "strict"
    suppress    = ["DNS-REQ-003"]
    categorization {
      baseline = "moderate"
    }
  }
}
```

Suppressed requirements are downgraded from errors to warnings. They still appear in
`terraform plan` output, creating an auditable trail that shows the requirement was
evaluated but intentionally excepted.

~> **Important:** Every suppressed requirement should have a corresponding entry in your
System Security Plan (SSP) or Plan of Action and Milestones (POA&M). Suppression without
documentation is a finding in itself during an assessment.

## Requirements Reference

The following table lists all 28 DNS security requirements enforced by the provider. Each
requirement is derived from one or more DISA STIG rules and maps to NIST 800-53 Rev 5
controls.

| ID | Title | Severity | NIST Controls | STIG Rules | Affected Resource |
|---|---|---|---|---|---|
| DNS-REQ-001 | DNSSEC must be enabled for authoritative zones | High | SC-20, SC-21, SC-23, SC-8, AU-10, CM-6, SI-10 | BIND-9X-001650, WDNS-22-000019 | `technitium_zone` |
| DNS-REQ-002 | Server-to-server transactions must use crypto auth (TSIG) | High | IA-3, SC-8 | BIND-9X-002010, WDNS-22-000062 | `technitium_zone` |
| DNS-REQ-003 | Audit records must be sent to remote syslog | High | AU-9 | BIND-9X-001910 | `technitium_server_settings` |
| DNS-REQ-004 | Zone transfers restricted to authorized secondaries | Medium | AC-10 | BIND-9X-001010, WDNS-22-000037 | `technitium_zone`, `technitium_server_settings` |
| DNS-REQ-005 | Recursion prohibited on authoritative name servers | Medium | CM-6, SC-5 | BIND-9X-001380, WDNS-22-000009 | `technitium_server_settings` |
| DNS-REQ-006 | Caching recursion restricted to known clients | Medium | SC-5 | BIND-9X-001740, WDNS-22-000011 | `technitium_server_settings` |
| DNS-REQ-007 | Query logging enabled | Medium | AU-12, AU-3, SC-24, SI-6 | BIND-9X-001110, WDNS-22-000004 | `technitium_server_settings` |
| DNS-REQ-008 | Logging must not be null | Medium | AU-9 | BIND-9X-001920, WDNS-22-000004 | `technitium_server_settings` |
| DNS-REQ-009 | Audit logs written to local file | Medium | AU-9 | BIND-9X-001900, WDNS-22-000004 | `technitium_server_settings` |
| DNS-REQ-010 | Log file retention meets minimum | Medium | AU-9 | BIND-9X-001890, WDNS-22-000115 | `technitium_server_settings` |
| DNS-REQ-011 | NSEC3 required for zone non-existence proofs | Medium | CM-6 | BIND-9X-001270, WDNS-22-000019 | `technitium_zone` |
| DNS-REQ-012 | FIPS-validated cryptography for DNSSEC | Medium | SC-13 | BIND-9X-002050, WDNS-22-000072 | `technitium_zone` |
| DNS-REQ-013 | Forwarder restrictions (US govt controlled only) | Medium | CM-6 | BIND-9X-001360, WDNS-22-000010 | `technitium_server_settings` |
| DNS-REQ-014 | QNAME minimization enabled | Medium | CM-6 | BIND-9X-002440 | `technitium_server_settings` |
| DNS-REQ-015 | Query name randomization (0x20 encoding) | Medium | CM-6 | BIND-9X-001490 | `technitium_server_settings` |
| DNS-REQ-016 | Primary servers notify authorized secondaries | Medium | CM-6 | BIND-9X-001390, WDNS-22-000068 | `technitium_zone` |
| DNS-REQ-017 | Separate TSIG key-pairs per server pair | Medium | IA-3 | BIND-9X-001700, WDNS-22-000035 | `technitium_tsig_key` |
| DNS-REQ-018 | Unique TSIG key per communicating host pair | Medium | IA-5 | BIND-9X-001190, WDNS-22-000035 | `technitium_tsig_key` |
| DNS-REQ-019 | TSIG/DNSSEC key rotation within one year | Medium | CM-6 | BIND-9X-001610 | `technitium_tsig_key` |
| DNS-REQ-020 | CNAME records must not cross to lesser security zones | Medium | CM-6 | BIND-9X-001580, WDNS-22-000030 | `technitium_record` |
| DNS-REQ-021 | Zone RRs must not reference FQDNs in other zones | Medium | CM-6 | BIND-9X-001590, WDNS-22-000029 | `technitium_record` |
| DNS-REQ-022 | Secure delegation via DS records for child zones | Medium | SC-20 | BIND-9X-001770, WDNS-22-000051 | `technitium_zone` |
| DNS-REQ-023 | Response rate limiting enabled | Medium | SC-5 | WDNS-22-000120 | `technitium_server_settings` |
| DNS-REQ-024 | Fetches-per-zone rate limiting | Medium | CM-6 | BIND-9X-002450 | `technitium_server_settings` |
| DNS-REQ-025 | Fetches-per-server rate limiting | Medium | CM-6 | BIND-9X-002460 | `technitium_server_settings` |
| DNS-REQ-026 | DNS cookies enabled | Medium | CM-6 | BIND-9X-002470 | `technitium_server_settings` |
| DNS-REQ-027 | Dynamic update client limits | Medium | AC-10 | BIND-9X-002480, WDNS-22-000001 | `technitium_server_settings` |
| DNS-REQ-028 | Management plane connections must use encrypted transport | Medium | SC-8 | SV-270286r1_rule | Provider |

## Cross-Resource Enforcement

The compliance engine does not evaluate resources in isolation. Several requirements span
multiple resource types, and the provider validates consistency across those boundaries.

### Example: TSIG Algorithm Compliance Across Zone and Key

Consider a zone configured for TSIG-signed transfers that references a separately managed
TSIG key:

```hcl
resource "technitium_tsig_key" "xfer" {
  key_name  = "xfer-key"
  algorithm = "hmac-sha1"  # Non-compliant in NSS mode
  secret    = var.tsig_secret
}

resource "technitium_zone" "secure" {
  name   = "secure.example.mil"
  type   = "Primary"
  dnssec = true

  zone_transfer {
    tsig_key_name = technitium_tsig_key.xfer.key_name
  }
}
```

In NSS mode, the provider will flag `technitium_tsig_key.xfer` for using `hmac-sha1`
(DNS-REQ-002, DNS-REQ-017). But it will also flag `technitium_zone.secure` because its
zone transfer configuration references a key that does not meet NSS cryptographic
requirements. This cross-resource validation prevents a compliant zone from being
silently paired with a non-compliant key.

In non-NSS strict mode, the TSIG key resource itself is still validated against
DNS-REQ-017 and DNS-REQ-018, but the cross-resource algorithm check is specific to NSS
environments where FIPS algorithm restrictions apply.

## Integration with Existing Workflows

### CI/CD Pipelines

STIG compliance checks integrate naturally into CI/CD pipelines because they run during
standard Terraform operations:

- **`terraform validate`** catches stateless STIG violations (configuration-only checks)
  before a plan is even generated. This is the fastest feedback loop and should be the
  first step in any pipeline.
- **`terraform plan`** evaluates stateful checks that require comparing planned values
  against current state. Plan output includes full STIG diagnostics with requirement IDs,
  NIST controls, and STIG rule references.
- **`terraform apply`** is blocked in `strict` mode if any STIG finding remains
  unresolved. In `warn` mode, apply proceeds but findings are logged.

A typical pipeline stage:

```bash
terraform init
terraform validate        # Catches stateless STIG violations
terraform plan -out=plan  # Catches stateful STIG violations
terraform apply plan      # Blocked if strict-mode findings exist
```

### Audit Evidence for RMF Packages

Every STIG diagnostic emitted by the provider includes:

- **Requirement ID** (e.g., DNS-REQ-001) for internal tracking
- **NIST 800-53 control mappings** (e.g., SC-20, SC-21) for RMF control correlation
- **STIG rule IDs** (e.g., BIND-9X-001650) for STIG checklist cross-reference
- **CCI mappings** for precise control decomposition

This metadata can be captured from `terraform plan` output (or JSON plan output) and
included directly in RMF evidence packages as proof that DNS infrastructure configuration
is continuously validated against applicable STIG requirements. Combined with Terraform
state and version control history, this creates a complete audit trail from security
requirement to infrastructure configuration.
