resource "technitium_zone" "rsa" {
  name = "legacy.example.com"
  type = "Primary"

  dnssec {
    enabled   = true
    algorithm = "RSA"
    nx_proof  = "NSEC3"
    # curve does not apply to RSA and is omitted.
  }
}
