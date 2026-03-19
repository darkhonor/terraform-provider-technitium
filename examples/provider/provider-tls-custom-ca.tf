terraform {
  required_providers {
    technitium = {
      source = "registry.terraform.io/darkhonor/technitium"
    }
  }
}

# HTTPS with a custom CA certificate
# Use when the Technitium server's TLS certificate is signed by an
# internal CA (e.g., enterprise PKI, self-signed CA for lab environments).
provider "technitium" {
  server_url   = var.technitium_server_url
  api_token    = var.technitium_api_token
  ca_cert_file = var.technitium_ca_cert_file
}

variable "technitium_server_url" {
  description = "Technitium DNS Server URL (HTTPS)"
  type        = string
  default     = "https://dns.example.com:5380"
}

variable "technitium_api_token" {
  description = "Technitium API token"
  type        = string
  sensitive   = true
}

variable "technitium_ca_cert_file" {
  description = "Path to PEM-encoded CA certificate file"
  type        = string
}
