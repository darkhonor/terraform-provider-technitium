terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# Provider configuration using environment variables only
# All TLS attributes support env var fallbacks when HCL is omitted.
#
# Environment variables (HCL takes precedence if both are set):
#   TECHNITIUM_SERVER_URL        - server_url
#   TECHNITIUM_API_TOKEN         - api_token
#   TECHNITIUM_SKIP_TLS_VERIFY   - skip_tls_verify (accepts "true"/"false"/"1"/"0")
#   TECHNITIUM_CACERT            - ca_cert_file
#   TECHNITIUM_CAPATH            - ca_cert_dir
#   TECHNITIUM_TLS_SERVER_NAME   - tls_server_name
#   TECHNITIUM_TLS_MIN_VERSION   - tls_min_version ("1.2" or "1.3")
#
# Usage:
#   export TECHNITIUM_SERVER_URL="https://dns.example.com:5380"
#   export TECHNITIUM_API_TOKEN="your-api-token"
#   export TECHNITIUM_CACERT="/path/to/ca.pem"
#   terraform plan
provider "technitium" {}
