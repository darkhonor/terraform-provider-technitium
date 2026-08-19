---
subcategory: ""
page_title: "technitium_allowed_zone Data Source - terraform-provider-technitium"
description: |-
  Checks whether a specific domain is present in the Technitium DNS Server
  allowed zone list. Returns a boolean exists attribute.
---

# technitium\_allowed\_zone (Data Source)

Checks whether a specific domain is present in the Technitium DNS Server allowed zone list. Returns a boolean `exists` attribute suitable for use in conditional expressions or compliance assertions.

## Example Usage

```terraform
data "technitium_allowed_zone" "check" {
  domain = "trusted.example.com"
}

output "is_allowed" {
  value = data.technitium_allowed_zone.check.exists
}
```

## Argument Reference

* `domain` - (Required, String) The domain name to check in the allowed zone list.

## Attributes Reference

* `id` - Allowed zone identifier (same as `domain`).

* `exists` - `true` if the domain is present in the allowed zone list, `false` otherwise.
