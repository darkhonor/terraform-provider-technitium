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
