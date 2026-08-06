# Release and compatibility contract

## Capability and actor

Operators can install a reproducible module version and determine whether it is supported with their Caddy and Go toolchain. Maintainers can publish changes with an explicit compatibility signal.

## Scope and dependencies

In scope:

- semantic version tags and release notes;
- version-pinned `xcaddy` installation examples;
- supported Caddy and Go versions;
- classification of configuration and behavior changes.

Out of scope:

- publishing prebuilt Caddy binaries;
- long-term support guarantees;
- automated deployment;
- dependency update policy beyond compatibility reporting.

The capability depends on Git tags, GitHub releases, CI verification, and the supported-version decision.

## Behavior and rules

- **R1:** Documentation provides a version-pinned installation command for production use.
- **R2:** Every published release identifies its supported Caddy and Go versions or ranges.
- **R3:** Release notes identify security-relevant changes, configuration additions, behavior changes, deprecations, and known migration actions.
- **R4:** Backward-incompatible changes to public Go APIs, JSON fields, Caddyfile directives, defaults, or request behavior require an appropriate semantic-version signal.
- **R5:** A release tag refers to a revision that passed the repository's required verification policy.
- **R6:** Unreleased main-branch installation may remain documented only as an explicitly unstable development option.

## Permissions and data

Only maintainers with repository release permission may publish tags or releases. Release artifacts and notes must not contain credentials, private dependency URLs, or local environment data.

## States and edge cases

- No stable release yet.
- Patch, minor, or major release.
- Security fix requiring expedited publication.
- Dependency update changing the minimum Go or Caddy version.
- Retracted or superseded release.
- Documentation viewed from `main` versus a tagged revision.

## Acceptance criteria

- **AC1:** Given a published release, when an operator follows the production installation instructions, then the command selects that exact module version.
- **AC2:** Given a published release, when its notes and compatibility section are inspected, then supported Go and Caddy versions are explicit.
- **AC3:** Given a change to a public configuration contract, when a release is prepared, then release notes classify the change and state any migration action.
- **AC4:** Given a release tag, when its target revision is checked, then all required release verification jobs passed for that revision.
- **AC5:** Given instructions for building from `main`, when documentation is inspected, then the path is labeled unstable and is not presented as the production default.
- **AC6:** Given a superseded or retracted release, when operators inspect release information, then the status and recommended replacement are explicit.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1, R6 | AC1, AC5 | Documentation link and command inspection |
| R2 | AC2 | Release template validation |
| R3, R4 | AC3 | Release-note checklist |
| R5 | AC4 | Release workflow/status check |
| Release recovery | AC6 | Release metadata inspection |

## Release decisions

- The first stable release is `v1.0.0`.
- Production releases support Go `>= 1.26.5` and Caddy `>= v2.11.4, < v3.0.0`.
- Releases are source-only: a Git tag and GitHub Release are published, without prebuilt Caddy binaries or project-provided checksums.
- The supported range is a compatibility commitment. CI must expand its version matrix before the range expands.

## Handoff state

READY
