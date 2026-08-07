# CI verification policy

## Capability and actor

Maintainers receive timely, reproducible evidence that a change builds, passes tests, remains race-safe, is tidy, and does not materially reduce test coverage. Contributors receive one clear failure signal per violated obligation.

## Scope and dependencies

In scope:

- required pull-request checks;
- test, race, coverage, build, vet, lint, tidy, and vulnerability evidence;
- removal of redundant full-suite execution;
- coverage regression policy;
- pinned verification tools.

Out of scope:

- release publication;
- deployment;
- product performance benchmarks;
- guaranteeing that external vulnerability databases are always available.

The capability depends on GitHub Actions, the Go toolchain, and the repository's integration-verification capability.

## Behavior and rules

- **R1:** Every pull request must produce build, test, race, vet, lint, module-tidiness, and vulnerability-check evidence according to the approved required-check policy.
- **R2:** Coverage is computed from a successful test execution and published as inspectable evidence.
- **R3:** The complete race-enabled suite is not repeated solely to generate coverage when equivalent evidence can be obtained without duplication.
- **R4:** Coverage policy detects material regression without encouraging tests that only inflate percentages.
- **R5:** Verification tool versions are pinned or updated through reviewable dependency automation.
- **R6:** A missing optional artifact does not obscure the original test failure.
- **R7:** Required checks use least-privilege permissions and do not expose repository secrets to untrusted pull-request code.

## Permissions and data

Normal CI jobs require read-only repository contents. Write permissions remain isolated to explicitly authorized automation. Coverage and logs must not contain secrets or live service data.

## States and edge cases

- All checks pass.
- Unit test or race failure.
- Coverage generation failure.
- Lint or vet failure.
- Untidy module files.
- Vulnerability database or network outage.
- Artifact absent because an earlier command failed.
- Fork pull request without secrets.
- Toolchain or action update.

## Acceptance criteria

- **AC1:** Given a valid pull request, when CI completes successfully, then each required verification obligation has current evidence for the tested revision.
- **AC2:** Given a test failure, when CI reports results, then the original failing test remains the primary failure and artifact handling does not replace it with a misleading error.
- **AC3:** Given a normal successful run, when job commands are inspected, then the complete race-enabled test suite executes no more than once per tested Go version unless explicitly justified.
- **AC4:** Given a material coverage regression under the approved policy, when CI runs, then the coverage check fails with the measured baseline and result.
- **AC5:** Given a non-material coverage change, when CI runs, then it does not fail solely due to incidental percentage noise under the approved tolerance.
- **AC6:** Given a fork pull request, when required checks run, then they require no write token or repository secret.
- **AC7:** Given an unavailable vulnerability service, when policy permits retry or a distinct infrastructure classification, then the result is not falsely reported as a code vulnerability.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1 | AC1 | Required-check matrix inspection |
| R2, R6 | AC2 | Forced test-failure workflow proof |
| R3 | AC3 | Workflow command inspection |
| R4 | AC4, AC5 | Synthetic baseline comparisons |
| R5 | AC1 | Action and tool version inspection |
| R7 | AC6 | Fork-event permission inspection |
| Dependency outage handling | AC7 | Controlled failure classification test |

## Policy decisions

- Coverage uses an absolute 70% minimum. This is intentionally a light threshold; no base-branch or diff-coverage comparison is used.
- `govulncheck` retries a detected external-service failure once. A repeated classified infrastructure failure is visible but does not block merging; an actual vulnerability or unclassified failure blocks merging.
- Required pull-request checks are lint, vet, race-enabled tests with coverage, build, module-tidiness, Caddy integration, and `govulncheck`.
- Caddy integration verification runs on every pull request, as well as `main` pushes and `v*` release tags.

## Handoff state

READY
