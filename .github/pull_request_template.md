## Summary

<!-- One or two sentences. What changes and why. -->

## Type of change

<!-- Check one or more. Match the type prefix of your commit subject. -->

- [ ] fix -- bug fix
- [ ] feat -- new feature
- [ ] chore -- non-functional change (deps, build, tooling)
- [ ] docs -- documentation only
- [ ] test -- test infra or coverage
- [ ] security -- security hardening
- [ ] refactor -- no behavior change

## Linked issue(s)

<!-- For example: Closes #NN, Refs #NN. Use "Closes" so GitHub auto-closes the issue on merge. -->

## Verification

<!-- Commands you ran, results, screenshots, exact output if relevant.
     Cite line numbers when referencing changed files. -->

## CHANGELOG

- [ ] Entry added under `[Unreleased]` in [CHANGELOG.md](../CHANGELOG.md)
- [ ] N/A (doc-only or chore)

## Compliance impact

<!-- For changes that touch DNS configuration, validators, or the
     security posture: any STIG / NIST 800-53 implication? Which
     DNS-REQ rules are affected, if any?
     For ergonomics-only, test-infra, or chore changes: write "N/A". -->

## Pre-flight

- [ ] Local unit tests pass (`make test`)
- [ ] Lint clean (`make lint`)
- [ ] No secrets, tokens, or internal hostnames in the diff
