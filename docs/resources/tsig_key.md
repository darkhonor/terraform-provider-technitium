---
subcategory: ""
page_title: "technitium_tsig_key Resource - terraform-provider-technitium"
description: |-
  Manages TSIG keys for authenticated DNS server-to-server transactions
  (zone transfers, dynamic updates).
---

# technitium\_tsig\_key (Resource)

Manages TSIG keys for authenticated DNS server-to-server transactions (zone transfers, dynamic updates).

~> **DoD / IC environments:** This resource enforces STIG controls when `stig_compliance` is enabled on the provider. Relevant controls include **DNS-REQ-002** (TSIG required for zone transfers) and **DNS-REQ-012** (FIPS-approved cryptographic algorithms). See the [STIG Compliance Guide](../guides/stig-compliance.md) for a full walkthrough.

~> **Sensitive state:** The `shared_secret` attribute is stored in the Terraform state file. Treat the state file as sensitive and restrict access accordingly.

## Example Usage

### Basic TSIG Key

```terraform
resource "technitium_tsig_key" "example" {
  key_name  = "transfer.example.com"
  algorithm = "hmac-sha256"
}
```

### NSS-Compliant TSIG Key

```hcl
# NSS mode restricts TSIG algorithms to FIPS-compliant options:
# hmac-sha256, hmac-sha384, hmac-sha512
resource "technitium_tsig_key" "nss" {
  key_name  = "transfer.example.mil"
  algorithm = "hmac-sha384"
}
```

## Argument Reference

* `key_name` - (Required, String) TSIG key name. (Forces replacement.)

* `algorithm` - (Required, String) HMAC algorithm. Valid values: `hmac-md5.sig-alg.reg.int`, `hmac-sha1`, `hmac-sha256`, `hmac-sha256-128`, `hmac-sha384`, `hmac-sha384-192`, `hmac-sha512`, `hmac-sha512-256`.

* `shared_secret` - (Optional, String, Sensitive, Computed) Base64-encoded shared secret. If omitted, the server generates one automatically.

~> **NSS environments:** When `nss = true` on the provider, algorithms are restricted to FIPS-compliant options: `hmac-sha256`, `hmac-sha384`, `hmac-sha512`.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - TSIG key identifier (same as `key_name`).

* `shared_secret` - Base64-encoded shared secret. Populated when the server generates the secret automatically.

## Import

TSIG keys can be imported using the key name.

```shell
terraform import technitium_tsig_key.example transfer.example.com
```
