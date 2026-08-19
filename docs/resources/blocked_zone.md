---
subcategory: ""
page_title: "technitium_blocked_zone Resource - terraform-provider-technitium"
description: |-
  Manages a single domain entry in the Technitium DNS Server blocked zone list.
---

# technitium\_blocked\_zone (Resource)

Manages a single domain entry in the Technitium DNS Server blocked zone list.

-> This resource uses a check-and-set pattern. If the domain already exists in the blocked list, Terraform adopts it.

## Example Usage

```terraform
resource "technitium_blocked_zone" "ads" {
  domain = "ads.example.com"
}
```

## Argument Reference

* `domain` - (Required, String) Domain name to block. (Forces replacement.)

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Blocked zone identifier (same as `domain`).

## Import

Blocked zone entries can be imported using the domain name.

```shell
terraform import technitium_blocked_zone.ads ads.example.com
```
