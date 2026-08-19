resource "technitium_zone" "going_insecure" {
  name = "retiring.example.com"
  type = "Primary"

  dnssec {
    # Keep the block and set enabled = false. Do not delete the block: the
    # acknowledgment below lives inside it.
    enabled = false

    change_acknowledgment = "unsigned"
  }
}
