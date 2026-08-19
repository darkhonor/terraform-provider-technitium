# Taking a signed zone insecure (removing DNSSEC).
#
# THIS IS DESTRUCTIVE AND ORDER-SENSITIVE. Unsigning destroys the zone's keys.
# If the parent zone still publishes a DS record for this zone when the
# signatures disappear, validating resolvers will treat the zone as BOGUS and
# refuse to resolve it — a self-inflicted outage that persists until the DS
# record expires from caches. RFC 6781 section 4.2.1.2 covers the going-insecure
# procedure; the provider warns about it at plan time in every enforcement mode.
#
# CORRECT ORDER
#
#   1. Remove the DS record for this zone from the PARENT zone.
#   2. Wait out the parent DS record's TTL, so no resolver still has it cached.
#   3. Withdraw any trust anchors distributed for this zone.
#   4. Only then apply the configuration below.
#
# THE TRAP: keep the dnssec block, set enabled = false
#
# The acknowledgment lives INSIDE the dnssec block, so deleting the block
# outright leaves nowhere to carry the consent and the plan is refused under
# strict enforcement. Keep the block with enabled = false and the
# acknowledgment for the unsigning apply, then remove the whole block on a
# later apply once the zone is already unsigned.
#
# "unsigned" is standing consent, not a one-shot token: its target space has a
# single member, so it cannot be scoped per-transition the way an algorithm
# token is. While it sits in configuration with no unsign pending, every plan
# warns that it will authorize a future unsign. Remove it once the unsign has
# converged. That removal warning is the one notice `silent` enforcement
# suppresses.

resource "technitium_zone" "going_insecure" {
  name = "retiring.example.com"
  type = "Primary"

  dnssec {
    # Do not delete this block to unsign. Set enabled = false and keep the
    # acknowledgment; remove the block on a later apply.
    enabled = false

    change_acknowledgment = "unsigned"
  }
}
