---
subcategory: ""
page_title: "technitium_catalog_membership Resource - terraform-provider-technitium"
description: |-
  Manages catalog zone membership (RFC 9432) for a Technitium DNS zone, so that
  secondary name servers slaving the catalog zone automatically provision the
  member zone.
---

# technitium\_catalog\_membership (Resource)

Manages catalog zone membership ([RFC 9432](https://datatracker.ietf.org/doc/html/rfc9432)) for a Technitium DNS zone. Assigning a member zone to a catalog zone lets secondary name servers that slave the catalog automatically provision the member zone, without an explicit zone definition on every secondary.

Valid for `Primary`, `Secondary`, `Stub`, and `Forwarder` member zones. The referenced catalog zone must be of type `Catalog` or `SecondaryCatalog`.

~> **Catalog settings shadow member-zone settings.** Once a zone joins a catalog, the catalog zone's `queryAccess`, `zoneTransfer`, and `notify` settings take precedence over the same settings declared on the member zone through `technitium_zone`, unless the corresponding per-member override flags are set. This provider does not yet expose those override flags, so `allow_transfer`, `notify`, and `query_access` on a member zone may be silently shadowed. The resource emits a plan-time warning whenever a membership is created or updated. Tracked in [#29](https://github.com/darkhonor/terraform-provider-technitium/issues/29).

-> **Ordering:** both the member zone and the catalog zone must exist by the time `terraform apply` reaches this resource. When all three resources live in the same configuration, the attribute references on `zone` and `catalog_zone` give Terraform the dependency ordering for free. Otherwise declare an explicit `depends_on`.

## Example Usage

```terraform
resource "technitium_zone" "cluster_catalog" {
  name = "cluster-catalog.dns.example.internal"
  type = "Catalog"
}

resource "technitium_zone" "lab" {
  name = "lab.example.internal"
  type = "Primary"

  dnssec {
    enabled = false
  }
}

resource "technitium_catalog_membership" "lab" {
  zone         = technitium_zone.lab.name
  catalog_zone = technitium_zone.cluster_catalog.name
}
```

## Argument Reference

* `zone` - (Required, String) Name of the member zone whose catalog membership is being managed. The zone must already exist when this resource is applied. Changing this forces replacement.

* `catalog_zone` - (Required, String) Name of the catalog zone this zone joins as a member. Must exist and be of type `Catalog` or `SecondaryCatalog`. The Technitium server returns an error at apply time if the catalog zone is missing or is a non-catalog type.

## Attributes Reference

In addition to the arguments above, the following computed attributes are exported:

* `id` - Catalog membership identifier (same as `zone`).

## Destroy Behavior

Destroying this resource unsets the member zone's catalog membership. It does **not** delete the member zone or the catalog zone; both survive with their records intact.

## Import

Catalog memberships are imported using the member zone name.

```shell
# Import an existing catalog membership by referencing the member zone name.
# The membership is read back from the Technitium API.
terraform import technitium_catalog_membership.lab lab.example.internal
```
