---
subcategory: ""
page_title: "technitium_tsig_key Data Source - terraform-provider-technitium"
description: |-
  Reads a TSIG key from the Technitium DNS Server by name. Use this data
  source to reference an existing TSIG key in zone transfer configuration
  without managing the key lifecycle in Terraform.
---

# technitium\_tsig\_key (Data Source)

Reads a TSIG key from the Technitium DNS Server by name. Use this data source to reference an existing TSIG key in zone transfer configuration without managing the key lifecycle in Terraform.

~> **Sensitive state:** The `shared_secret` attribute is stored in Terraform state. Treat the state file as sensitive and restrict access accordingly.

## Example Usage

```terraform
data "technitium_tsig_key" "transfer" {
  key_name = "transfer.example.com"
}

resource "technitium_zone" "secondary" {
  name = "example.com"
  type = "Secondary"

  primary_zone_transfer_tsig_key_name = data.technitium_tsig_key.transfer.key_name
}
```

## Argument Reference

* `key_name` - (Required, String) The TSIG key name to look up.

## Attributes Reference

* `id` - TSIG key identifier (same as `key_name`).

* `algorithm` - HMAC algorithm of the TSIG key (e.g., `hmac-sha256`, `hmac-sha384`, `hmac-sha512`).

* `shared_secret` - (Sensitive) Base64-encoded shared secret for this TSIG key.
