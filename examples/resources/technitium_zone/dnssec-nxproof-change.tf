resource "technitium_zone" "nxproof" {
  name = "walkable.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"
    curve     = "P256"

    # Changed from "NSEC". Converts in place; keys and DS records survive.
    nx_proof = "NSEC3"
  }
}
