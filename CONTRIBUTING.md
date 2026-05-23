# Contributing to terraform-provider-technitium

Thanks for your interest in contributing. This provider serves operators
who want STIG-aligned Technitium DNS Server infrastructure as code, plus
homelab tinkerers who want a clean Terraform path to a self-hosted DNS
server. Both audiences are welcome, and the contribution process tries
not to force one path on the other.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
By participating, you agree to uphold it. Reports of conduct issues go
to `conduct@darkhonor.com`.

We expect everyone in the community to treat each other with respect.
There is no place here for hate, harassment, or bullying in any form.

## Asking for help vs. filing an issue

- **Usage questions** (how do I configure `technitium_zone`? what does
  `enforcement = "warn"` actually do?): start with the [provider docs](./docs/)
  and the [STIG Compliance Guide](./docs/guides/stig-compliance.md). If
  those don't answer your question, file an Enhancement issue with a
  "docs gap" framing — that helps the project improve.
- **Bug** (provider misbehaves, errors are confusing, drift appears
  where it shouldn't): file a Bug issue with the template fields.
- **Security vulnerability**: do NOT open a public issue. See
  [Reporting a security vulnerability](#reporting-a-security-vulnerability)
  below.

## Reporting a bug

Use the [Bug report](https://github.com/darkhonor/terraform-provider-technitium/issues/new?template=bug.yml)
template. The form asks for the minimum the maintainer needs to diagnose:
provider version, Terraform version, Technitium DNS Server version, OS,
what happened, what you expected, and a minimal reproducing HCL snippet.
Other fields (TLS mode, STIG enforcement mode, command output) are
optional — fill them in if you know the answer; skip them if you don't.

## Reporting a security vulnerability

See [.github/SECURITY.md](.github/SECURITY.md) for the security policy.
**Do not file a public issue for vulnerabilities.** Use GitHub's
[private vulnerability reporting](https://github.com/darkhonor/terraform-provider-technitium/security/advisories/new)
flow so the conversation stays private until a fix is available.

## Suggesting an enhancement

Use the [Enhancement](https://github.com/darkhonor/terraform-provider-technitium/issues/new?template=enhancement.yml)
template. The form asks for a summary, the use case (homelab or
production context welcome), and a proposed solution. Optional fields
let you pre-mark the affected surface, link Technitium API endpoints,
and call out STIG / NIST 800-53 implications when applicable.

## Development setup

### Prerequisites

- [Go](https://go.dev/) >= 1.26.3 (matches the `go` directive in `go.mod`)
- [Docker](https://www.docker.com/) (for acceptance tests)
- [Terraform CLI](https://developer.hashicorp.com/terraform/install) (used by `terraform-plugin-testing`)
- GNU Make

### Clone and build

```bash
git clone https://github.com/darkhonor/terraform-provider-technitium.git
cd terraform-provider-technitium
make build
```

### Running unit tests

```bash
make test
```

Unit tests run entirely offline.

### Running acceptance tests

The acceptance suite spins up a Technitium DNS Server container via
docker-compose, provisions a fresh API token, and exercises every
resource against a live server.

```bash
make testacc-up      # HTTP-mode acceptance suite
make testacc-down    # teardown

make testacc-up-tls  # HTTPS-mode acceptance suite (TLS fixtures + STIG-strict tests)
make testacc-down-tls
```

The test container runs as your host user (issue #36), and the token
bootstrap helper pipes the admin password to `curl` on stdin rather
than via argv or env (issue #35) — so neither shows up in process
listings during the run.

### FIPS build

```bash
make build-fips    # GOEXPERIMENT=boringcrypto build
make test-fips     # FIPS-mode unit tests
```

### Regenerating docs

The provider docs under `docs/` are generated from the templates under
`templates/` plus the resource schema:

```bash
make generate
```

If you change a resource schema, an example, or a template, regenerate
the docs and commit the result. CI's `Verify Docs` job will fail otherwise.

## Code style

- Go code is formatted by `gofmt` and linted by `golangci-lint`.
- The lint configuration lives at [.golangci.yml](./.golangci.yml).
- CI fails on lint violations; run `make lint` locally before pushing.
- Tests are written in the standard `testing` package style for unit
  tests and via `terraform-plugin-testing` for acceptance tests.

## Commit message conventions

This repo uses [Conventional Commits](https://www.conventionalcommits.org/).
The type prefix carries information for the changelog generator and for
human readers scanning `git log`. Examples from the actual repo history:

```
fix(security): eliminate credential argv/env exposure in test harness (closes #35)
security(ci): enforce GitHub Actions SHA pinning
test(infra): run Technitium test container as non-root host user (closes #36)
fix(deps): update module github.com/hashicorp/terraform-plugin-testing to v1.16.0
chore(deps): pin technitium/dns-server docker tag
```

Common types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`,
`security`. Scope is optional but encouraged (`fix(client):`,
`feat(catalog):`, `chore(deps):`, `docs(readme):`).

Signed commits are not required.

## Pull request process

### Branch naming

- `feature/issue-NN-short-slug` for new features
- `fix/issue-NN-short-slug` for bug fixes
- `docs/issue-NN-short-slug` for documentation
- `security/short-slug` for supply-chain or hardening changes
- `chore/short-slug` for renovate-bot, build, or non-functional changes

If an issue number is not available, omit the `issue-NN` segment.

### CI gates

Every PR must pass:

- `Lint` — `golangci-lint`
- `Unit Tests` — `make test`
- `FIPS Build` — `GOEXPERIMENT=boringcrypto go build ./...`
- `Acceptance Tests (TLS)` — full TLS-mode acceptance suite
- `Security Scan` — `gosec` + `govulncheck`
- `CodeQL` — static analysis
- `Verify action SHA pins` — `pinact` enforces full 40-char SHA pins on every `uses:` reference
- `Verify Docs` — generated docs match templates + schema

### CHANGELOG entry

Add an entry to the `[Unreleased]` section of [CHANGELOG.md](./CHANGELOG.md)
in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Use
the appropriate subsection: `Added`, `Changed`, `Deprecated`, `Removed`,
`Fixed`, `Security`, `Known limitations`, or `Upgrade Notes`.

Documentation-only and chore PRs may skip the CHANGELOG entry.

### Review and merge

- All CI gates must be green before review.
- At least one maintainer approval is required.
- Squash-merge is the default; the squashed commit subject should follow
  Conventional Commits.

## Compliance posture

This provider markets STIG-aligned DNS hardening with full NIST 800-53
control traceability. When proposing a feature or fixing a bug:

- If the change touches DNS configuration that the embedded validators
  evaluate, consider whether a DNS-REQ validator should be added,
  modified, or extended. See the [STIG Compliance Guide](./docs/guides/stig-compliance.md)
  for the requirement framework.
- New validators must include test coverage in
  `internal/provider/validators/`.
- Validator changes that affect the NSS / CNSSI 1253 baseline must be
  noted in the PR description so the categorization tables stay accurate.

Ergonomics-only changes and test-infra work have no compliance impact;
the PR template lets you mark this explicitly.

## License

This project is licensed under the [Mozilla Public License 2.0](./LICENSE).
By submitting a contribution, you affirm that you have the right to
license it under MPL-2.0 (inbound = outbound).

## LLM attribution

If you used an LLM-based coding assistant (Claude Code, GitHub Copilot,
Cursor, Aider, etc.) to materially contribute to a commit, add a
`Co-Authored-By:` trailer attributing the tool. This keeps the audit
trail explicit without favoring any particular provider:

```
Co-Authored-By: <Tool Name> <noreply@<vendor>.com>
```

Pick the email the tool's documentation recommends, or use the vendor's
`noreply@` address if none is given. Examples (illustrative, not
prescriptive):

- `Co-Authored-By: GitHub Copilot <noreply@github.com>`
- `Co-Authored-By: Cursor <noreply@cursor.sh>`
- `Co-Authored-By: Claude Code <noreply@anthropic.com>`
