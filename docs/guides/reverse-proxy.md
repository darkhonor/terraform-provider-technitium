---
subcategory: ""
page_title: "Reverse Proxies and Load Balancers - Technitium DNS Server Provider"
description: |-
  How to configure a reverse proxy or load balancer in front of Technitium DNS Server so the provider works through it.
---

# Running Behind a Reverse Proxy or Load Balancer

A reverse proxy, WAF, or load balancer in front of Technitium DNS Server is configured outside
Terraform. The provider cannot see that configuration, but it depends on it: a proxy that
drops a header, caps request bodies, or redirects requests changes what the provider sees and
how it fails. This guide lists what the proxy must allow and how each mistake shows up.

## What the provider sends

Every request goes to a path under `/api/`, on the scheme, host, and port named by `server_url`.

| | Default (`Authorization: Bearer`) | `legacy_token_auth = true` |
|---|---|---|
| Reads (including the connectivity check at configure time) | `GET`, identifiers in the query string | `POST`, form body |
| Writes | `POST`, form body (`application/x-www-form-urlencoded`) | `POST`, form body |
| API token | `Authorization` header | `token` field in the form body |
| Blocked/allowed list export | `GET`, plain-text response | `POST`, plain-text response |

Request timeout is 30 seconds. Form bodies can be large: a blocked or allowed zone import sends
the whole list in one request (about 1.7 MB for 60,000 domains).

## Proxy checklist

| The proxy must | If it does not, the provider reports |
|---|---|
| Allow `GET` and `POST` on `/api/*` | `unexpected HTTP status 403` on writes (default mode) or on every request (`legacy_token_auth`) |
| Pass the `Authorization` header to Technitium unchanged | `technitium API error (status=invalid-token)` (default mode) |
| Accept request bodies large enough for your largest list import | `unexpected HTTP status 413` on import |
| Allow upstream reads and writes to take at least 30 seconds | `unexpected HTTP status 504` or a timeout |
| Offer TLS 1.3, or the provider sets `tls_min_version = "1.2"` | `tls: protocol version not supported` (shown as "TLS 1.3 not supported by the server") |
| Route on the host name in `server_url` and serve a certificate for it | `unexpected HTTP status 404`, or a certificate error |

Also:

* **Do not log the `Authorization` header or request bodies.** They carry the API token, record
  values, comments, and secrets such as `proxy_password`. The default access-log formats of
  nginx and Traefik log neither.
* **WAF rules may block DNS data.** TXT values (SPF, DKIM, DMARC), CAA values, and free-text
  comments can match generic injection rules. A blocked request appears as an HTTP 403. Exempt
  `/api/` from body inspection, or tune the rule, rather than changing the record.
* **Authentication middleware** (forward-auth, basic auth) that reads or replaces the
  `Authorization` header breaks default-mode authentication. Put it on other paths or hosts.
* **Trust the proxy's certificate.** If it is issued by a private CA, point `ca_cert_file` or
  `ca_cert_dir` at that CA. If `server_url` uses an IP address or a name the certificate does
  not cover, set `tls_server_name` to the certificate's name. Avoid `skip_tls_verify` outside
  testing.

## Redirects

Set `server_url` to the address the proxy actually serves, including `https://` and any port.
The provider follows a redirect only when the scheme, host, and port stay the same (a path
change). It refuses every other redirect and names both URLs:

```
refusing redirect from http://dns.example.test/api/settings/get to https://dns.example.test/api/settings/get: set server_url to the final address
```

This includes:

* an `http://` to `https://` redirect from the proxy;
* Technitium's own HTTP-to-HTTPS redirect (`web_service_http_to_tls_redirect`), which answers
  with a 307;
* a redirect to a different host name, even one that reaches the same server;
* a redirect to another port on the same host, which can be a different service.

Refusing these keeps the API token, and the TLS settings you configured, on the address
`server_url` names. A redirect that changes `http://` to `https://` would otherwise connect
without your `tls_min_version`, `ca_cert_file`, or `skip_tls_verify` settings.

Host names are compared as written: `dns.example.test.` (trailing dot) and `dns.example.test`
are different hosts, and so are two spellings of the same IP address. An omitted port equals
the scheme's default, so `https://dns.example.test` and `https://dns.example.test:443` match.

A same-origin 301, 302, or 303 re-sends a write as a `GET` without its body. Most writes then fail
with `Parameter '...' missing.`; a write that takes no parameters, such as flushing the blocked
or allowed list, can run as a `GET`. Avoid these redirects on `/api/`.

## Error pages

When the proxy answers instead of Technitium, the provider reports the HTTP status and the first
512 bytes of the page, with the API token, login password, and any secret sent in that request
replaced by `[REDACTED]`. A blocked or allowed list read never turns an error page into a list
of domains: an HTML page, a JSON body, or a non-200 status is an error.

## Example: nginx

TLS termination at nginx, Technitium's web service on plain HTTP inside a private network:

```nginx
server {
    listen 443 ssl;
    server_name dns.example.test;

    ssl_certificate     /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    ssl_protocols       TLSv1.3;

    # Blocked/allowed list imports send the whole list in one form body.
    client_max_body_size 16m;

    location /api/ {
        proxy_pass         http://technitium:5380;
        proxy_set_header   Host $host;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}
```

nginx passes the `Authorization` header through by default. Its default
`client_max_body_size` is 1 MB, which a large list import exceeds.

## Example: Traefik

Static configuration (`traefik.yml`):

```yaml
entryPoints:
  websecure:
    address: ":443"
providers:
  file:
    filename: /etc/traefik/dynamic.yml
```

Dynamic configuration (`dynamic.yml`):

```yaml
http:
  routers:
    technitium:
      rule: "Host(`dns.example.test`) && PathPrefix(`/api/`)"
      entryPoints: [websecure]
      service: technitium
      tls: {}
  services:
    technitium:
      loadBalancer:
        servers:
          - url: "http://technitium:5380"
tls:
  certificates:
    - certFile: /etc/traefik/tls/cert.pem
      keyFile: /etc/traefik/tls/key.pem
  options:
    default:
      minVersion: VersionTLS13
```

The `Host()` rule means `server_url` must use `dns.example.test`. A request to the proxy's IP
address gets a 404 and Traefik's default certificate.

Provider configuration for either example:

```hcl
provider "technitium" {
  server_url   = "https://dns.example.test"
  api_token    = var.technitium_api_token
  ca_cert_file = "/etc/pki/technitium-proxy-ca.pem" # only if the proxy certificate is from a private CA
}
```

Both examples were tested with nginx `stable-alpine` and Traefik v3.5 in front of Technitium
DNS Server 15.5.1, in default and `legacy_token_auth` modes, including a 60,000-domain blocked
list import.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `refusing redirect from ... to ...` | `server_url` is not the final address; use the `https://` URL the proxy serves. |
| `technitium API error (status=invalid-token)` with a valid token | The proxy strips or replaces `Authorization`, or Technitium is older than 15.0 (set `legacy_token_auth = true`). |
| `unexpected HTTP status 413` | The proxy's request body limit is below the size of the list import. |
| `unexpected HTTP status 403` | A WAF or method rule blocks `POST` or the request body. |
| `unexpected HTTP status 404` | The proxy did not match the host or path; check that `server_url` uses the routed host name and `/api/` reaches Technitium. |
| `unexpected HTTP status 502` or `504` | The proxy cannot reach Technitium, or its upstream timeout is shorter than the request. |
| `TLS 1.3 not supported by the server` | The proxy offers only TLS 1.2; enable TLS 1.3 or set `tls_min_version = "1.2"`. |
| Certificate signed by unknown authority | Set `ca_cert_file` or `ca_cert_dir` to the CA that issued the proxy certificate. |
| `Parameter '...' missing.` on writes | A same-host 301/302/303 dropped the request body. |

See also [Upgrading to v1.3](upgrading-to-v1.3.md) for the transport changes behind these rules.
