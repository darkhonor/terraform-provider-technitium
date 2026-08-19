resource "technitium_zone" "rotating" {
  name = "rotate.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "ECDSA"

    # Changed from "P256". Requires the acknowledgment below.
    curve    = "P384"
    nx_proof = "NSEC3"

    # Authorizes this transition only. Remove once the DS records are republished.
    change_acknowledgment = "ECDSA/P384"
  }
}
