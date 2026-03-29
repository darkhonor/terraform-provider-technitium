resource "technitium_record" "web1" {
  zone      = "example.com"
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.100"
  overwrite = false
}

resource "technitium_record" "web2" {
  zone      = "example.com"
  name      = "www.example.com"
  type      = "A"
  value     = "192.168.1.101"
  overwrite = false
}
