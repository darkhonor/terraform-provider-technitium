---
subcategory: ""
page_title: "technitium_blocked_zone Data Source - terraform-provider-technitium"
description: |-
  Checks whether a specific domain is present in the Technitium DNS Server
  blocked zone list. Returns a boolean exists attribute.
---

# technitium\_blocked\_zone (Data Source)

Checks whether a specific domain is present in the Technitium DNS Server blocked zone list. Returns a boolean `exists` attribute suitable for use in conditional expressions or compliance assertions.

## Example Usage

```terraform
data "technitium_blocked_zone" "check" {
  domain = "ads.example.com"
}

output "is_blocked" {
  value = data.technitium_blocked_zone.check.exists
}
```

## Argument Reference

* `domain` - (Required, String) The domain name to check in the blocked zone list.

## Attributes Reference

* `id` - Blocked zone identifier (same as `domain`).

* `exists` - `true` if the domain is present in the blocked zone list, `false` otherwise.
