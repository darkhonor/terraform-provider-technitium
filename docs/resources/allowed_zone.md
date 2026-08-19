---
subcategory: ""
page_title: "technitium_allowed_zone Resource - terraform-provider-technitium"
description: |-
  Manages a single domain entry in the Technitium DNS Server allowed zone list.
---

# technitium\_allowed\_zone (Resource)

Manages a single domain entry in the Technitium DNS Server allowed zone list.

-> This resource uses a check-and-set pattern. If the domain already exists in the allowed list, Terraform adopts it.

## Example Usage

```terraform
resource "technitium_allowed_zone" "trusted" {
  domain = "trusted.example.com"
}
```

## Argument Reference

* `domain` - (Required, String) Domain name to allow. (Forces replacement.)

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Allowed zone identifier (same as `domain`).

## Import

Allowed zone entries can be imported using the domain name.

```shell
terraform import technitium_allowed_zone.trusted trusted.example.com
```
