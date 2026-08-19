resource "technitium_zone" "eddsa" {
  name = "ed.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "EDDSA"
    curve     = "ED448"
    nx_proof  = "NSEC3"
  }
}
