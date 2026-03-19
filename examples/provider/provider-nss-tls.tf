terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with NSS (National Security Systems) compliance
# NSS environments enforce the strictest TLS requirements:
#   - HTTPS is mandatory (HTTP URLs produce an error)
#   - TLS 1.3 is mandatory (no fallback to 1.2)
#   - skip_tls_verify is prohibited
#   - CA certificates must be explicitly configured
#
# Typical DoD deployment with multiple CA trust chains:
#   - ca_cert_file: server-specific issuing CA
#   - ca_cert_dir: DoD Root CA bundle + enterprise intermediate CAs
provider "technitium" {
  server_url   = var.technitium_server_url
  api_token    = var.technitium_api_token
  ca_cert_file = var.technitium_ca_cert_file
  ca_cert_dir  = var.technitium_ca_cert_dir

  stig_compliance {
    enabled     = true
    nss         = true
    enforcement = "strict"

    categorization {
      confidentiality = "high"
      integrity       = "high"
      availability    = "moderate"
    }
  }
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS required for NSS)"
  type        = string
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}

variable "technitium_ca_cert_file" {
  description = "Path to PEM-encoded CA certificate for the Technitium server"
  type        = string
}

variable "technitium_ca_cert_dir" {
  description = "Path to directory of DoD Root CA and intermediate CA certificates"
  type        = string
  default     = "/etc/pki/dod-certs"
}
