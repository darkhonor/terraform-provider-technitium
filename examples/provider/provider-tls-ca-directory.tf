terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with a CA certificate directory
# Use when multiple CA trust chains are needed — common in DoD environments
# where internal enterprise PKI, external PKI, and DoD Root CAs coexist.
# All PEM files in the directory are loaded; non-PEM files are skipped.
provider "technitium" {
  server_url  = var.technitium_server_url
  api_token   = var.technitium_api_token
  ca_cert_dir = var.technitium_ca_cert_dir
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS)"
  type        = string
  default     = "https://dns.example.mil:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}

variable "technitium_ca_cert_dir" {
  description = "Path to directory of PEM-encoded CA certificate files"
  type        = string
  default     = "/etc/pki/ca-trust/source/anchors"
}
