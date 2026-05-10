# Manage catalog zone membership so that secondary name servers slaving the
# catalog will automatically provision the member zone.
#
# The catalog zone (type = "Catalog") and the member zone (type = "Primary",
# "Secondary", "Stub", or "Forwarder") must exist by the time
# `terraform apply` reaches this resource. When all three resources are in
# the same configuration (as below), Terraform's implicit dependency graph
# orders the zone resources before the membership resource via the attribute
# references on `zone` and `catalog_zone`.

resource "technitium_zone" "cluster_catalog" {
  name = "cluster-catalog.dns.example.internal"
  type = "Catalog"

  dnssec {
    enabled = false
  }
}

resource "technitium_zone" "lab" {
  name = "lab.example.internal"
  type = "Primary"

  dnssec {
    enabled = false
  }
}

# IMPORTANT — catalog inheritance:
#
# Once a zone is added to a catalog, the catalog zone's queryAccess,
# zoneTransfer, and notify settings take effect on the member zone unless
# the corresponding override flags are set on the member. This provider
# does not yet expose those override flags. Any matching settings declared
# on technitium_zone.lab (zone_transfer_allowed_networks, query_access,
# notify_addresses, etc.) may be silently shadowed by the catalog zone.
#
# See:
# https://github.com/darkhonor/terraform-provider-technitium/issues/29
resource "technitium_catalog_membership" "lab" {
  zone         = technitium_zone.lab.name
  catalog_zone = technitium_zone.cluster_catalog.name
}
