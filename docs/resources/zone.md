---
subcategory: ""
page_title: "technitium_zone Resource - terraform-provider-technitium"
description: |-
  Manages a DNS zone on the Technitium DNS Server. Supports Primary, Secondary, Stub,
  and Forwarder zone types with optional DNSSEC signing and TSIG-authenticated zone
  transfers.
---

# technitium\_zone (Resource)

Manages a DNS zone on the Technitium DNS Server. Supports Primary, Secondary, Stub, and Forwarder zone types with optional DNSSEC signing and TSIG-authenticated zone transfers.

~> **DoD / IC environments:** This resource enforces multiple STIG controls when `stig_compliance` is enabled on the provider. Relevant controls include **DNS-REQ-001** (DNSSEC signing), **DNS-REQ-002** (TSIG-authenticated zone transfers), **DNS-REQ-004** (zone transfer ACL), **DNS-REQ-011** (NSEC3 proof of non-existence), **DNS-REQ-012** (FIPS-approved cryptographic algorithms), and **DNS-REQ-016** (notify configuration). See the [STIG Compliance Guide](../guides/stig-compliance.md) for a full walkthrough.

## Example Usage

### Basic Primary Zone

```terraform
resource "technitium_zone" "example" {
  name = "example.com"
  type = "Primary"
}
```

### Secondary Zone with TSIG Authentication

```hcl
resource "technitium_tsig_key" "transfer" {
  key_name  = "transfer.example.com"
  algorithm = "hmac-sha256"
}

resource "technitium_zone" "secondary" {
  name = "example.com"
  type = "Secondary"

  primary_zone_transfer_tsig_key_name = technitium_tsig_key.transfer.key_name
}
```

### DNSSEC-Enabled Zone

```hcl
resource "technitium_zone" "signed" {
  name = "secure.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"
    nx_proof  = "NSEC3"
  }
}
```

### NSS-Compliant Zone

```hcl
resource "technitium_tsig_key" "nss_transfer" {
  key_name  = "nss-transfer.example.mil"
  algorithm = "hmac-sha384"
}

resource "technitium_zone" "nss" {
  name = "example.mil"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P384"
    nx_proof  = "NSEC3"
  }

  zone_transfer_tsig_key_names = [
    technitium_tsig_key.nss_transfer.key_name,
  ]

  notify         = ["10.0.1.2", "10.0.1.3"]
  allow_transfer = ["10.0.1.2", "10.0.1.3"]
}
```

## Argument Reference

* `name` - (Required, String) Domain name for the zone. (Forces replacement.)

* `type` - (Required, String) Zone type. Valid values: `Primary`, `Secondary`, `Stub`, `Forwarder`. (Forces replacement.)

* `soa_serial_date_scheme` - (Optional, Boolean) Use date-based SOA serial numbering. Default: `true`.

* `notify` - (Optional, List of String) IP addresses to notify on zone changes.

* `allow_transfer` - (Optional, List of String) IP addresses allowed to perform zone transfers.

* `zone_transfer_tsig_key_names` - (Optional, List of String) TSIG key names authorized to perform zone transfers. Only valid for `Primary`, `Secondary`, `Forwarder`, and `Catalog` zones.

* `primary_zone_transfer_tsig_key_name` - (Optional, String) TSIG key name for authenticating zone transfers from the primary server. Only valid for `Secondary`, `SecondaryForwarder`, and `SecondaryCatalog` zones.

* `dnssec` - (Optional, Block) DNSSEC signing configuration. Only valid for `Primary` zones. See [dnssec](#dnssec) below.

### dnssec

~> **`Primary` zones only.** Technitium signs `Primary` zones and refuses every other type, so a `dnssec` block on a `Secondary`, `Stub`, `Forwarder`, `Catalog`, `SecondaryForwarder`, or `SecondaryCatalog` zone is rejected at plan time. A `Secondary` serves the signed data it receives from its primary by zone transfer rather than signing locally, so sign the zone on the primary instead.

The `dnssec` block supports the following arguments:

* `enabled` - (Optional, Boolean) Enable DNSSEC signing for the zone. Default: `true`.

* `algorithm` - (Optional, String) DNSSEC signing algorithm. Valid values: `ECDSA`, `EDDSA`, `RSA`. Default: `"ECDSA"`.

* `curve` - (Optional, String) Elliptic curve for `ECDSA` (`P256`, `P384`) or `EDDSA` (`ED25519`, `ED448`). Default: `"P256"`.

  -> **NSS environments:** When `nss = true` on the provider, `ECDSA` with `P256` is rejected. Use `P384` to comply with CNSSI 1253.

* `nx_proof` - (Optional, String) Proof of non-existence mechanism. Valid values: `NSEC`, `NSEC3`. Default: `"NSEC3"`. Changing this on a signed zone converts in place — no key regeneration.

* `change_acknowledgment` - (Optional, String) Operator acknowledgment authorizing a destructive DNSSEC transition on this zone. Set to `"<ALGORITHM>/<CURVE>"` (e.g. `"ECDSA/P384"`; bare `"RSA"` for RSA) to authorize an unsign/re-sign to those parameters (the value is compared literally and case-sensitively, exactly as the provider spells it), or `"unsigned"` to authorize unsigning (standing consent — remove after use; a stale value draws a removal warning on every plan except under `silent` enforcement). Required for in-place `algorithm`/`curve` changes in every posture, and for unsigning under `strict` enforcement. See the [STIG Compliance Guide](../guides/stig-compliance.md).

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Zone identifier (same as `name`).

* `soa_serial` - Current SOA serial number.

* `status` - Zone status. Value is `enabled` or `disabled`.

* `dnssec_status` - DNSSEC signing status as reported by the server (e.g., `Unsigned`, `Signed`).

## Import

DNS zones can be imported using the zone name.

```shell
terraform import technitium_zone.example example.com
```
