# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < latest | No                |

## Reporting a Vulnerability

If you discover a security vulnerability in this provider, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use [GitHub's private vulnerability reporting](https://github.com/darkhonor/terraform-provider-technitium/security/advisories/new) to submit your report. This keeps the conversation private between you and the maintainers until a fix is available.

In your report, please include:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

You should receive a response within 72 hours. We will work with you to understand the issue and coordinate a fix and disclosure timeline.

## Scope

This security policy covers:

- The Terraform provider binary and its source code
- The STIG compliance validation engine
- Credential handling (API tokens, TSIG keys)
- GitHub Actions workflow integrity

This policy does **not** cover:

- The Technitium DNS Server itself (report to [TechnitiumSoftware](https://github.com/TechnitiumSoftware/DnsServer))
- HashiCorp Terraform core (report to [HashiCorp](https://www.hashicorp.com/security))

## GitHub Actions Pinning Policy

All GitHub Actions `uses:` references must be pinned to a full 40-character
commit SHA. Human-readable versions may be kept only as trailing comments, for
example:

```yaml
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
```

Do not pin actions by mutable tags such as `@v1`, `@v4`, or `@main`.
Dependabot/Renovate manages SHA bumps for the `github_actions` ecosystem; the
CI pinning gate prevents future workflow changes from weakening this
supply-chain control.
