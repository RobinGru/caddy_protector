# Feature implementation status

This file is the resumable index for the feature plan. Update it only from observed repository evidence; do not infer progress from elapsed time, commit messages, or an unchecked task list.

- Observed revision: `e0ad773e272fb5e555b5e896f2de8ba89dda9de5`
- Last verified implementation revision: `e0ad773e272fb5e555b5e896f2de8ba89dda9de5`
- Current focus: `verification-abuse-resilience`
- Next safe action: Commit the verified verification limiter, then rerun its focused tests on that commit and record its full revision.

## State definitions

| State | Meaning |
| --- | --- |
| `PROPOSED` | Specification or required decisions are incomplete. |
| `READY` | Specification and decisions are ready; implementation has not started. |
| `IN PROGRESS` | Implementation is actively observed in the repository. |
| `BLOCKED` | A named condition prevents the next action. |
| `VERIFICATION` | Implementation appears complete, but final evidence is incomplete. |
| `DONE` | All acceptance criteria have direct proof on the verified revision. |
| `ABANDONED` | An authorized owner stopped or replaced the feature. |

## Feature index

| Priority | Feature | State | Specification | Decision | Implementation evidence | Verification evidence | Blocker | Next action |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | [Outbound request safety](outbound-request-safety.md) | `DONE` | `READY` | `CONFIRMED` | Shared redirect and address policy in `outbound.go`; Cap and source clients use it. | `go test ./...`, `go vet ./...`, and `git diff --check HEAD^ HEAD` passed on `01b3eafee0ead24f4dfa85185b6a88d3374b01d8`; direct tests cover AC1–AC8. | None. | Select the next feature from this index. |
| 2 | [Caddy integration verification](caddy-integration-verification.md) | `DONE` | `READY` | `CONFIRMED` | Tagged local Custom-Caddy harness and CI integration job use `xcaddy v0.4.5` plus synthetic Cap and recording upstream services. | `PATH=/home/rene/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin go test -tags=integration -count=1 -timeout=5m ./...`, `go vet -tags=integration ./...`, and `git diff --check HEAD^ HEAD` passed on `e0ad773e272fb5e555b5e896f2de8ba89dda9de5`; direct assertions cover AC1–AC8. | None. | Select the next feature from this index. |
| 3 | [Verification abuse resilience](verification-abuse-resilience.md) | `VERIFICATION` | `READY` | `CONFIRMED` | Bounded concurrency-safe per-IP token bucket with burst 15, 3-second refill, 429 retry guidance, expiry cleanup, and lifecycle reset. | `go test -race -count=1 -run '^TestVerificationAbuseResilienceAC' ./...` and `go vet ./...` passed on the uncommitted worktree based on `e0ad773e272fb5e555b5e896f2de8ba89dda9de5`; direct tests cover AC1–AC8. | No committed revision exists for final revision-bound verification. | Commit the limiter, then rerun its focused tests on that commit and record its full revision. |
| 4 | [Operational metrics](operational-metrics.md) | `PROPOSED` | `DRAFT` | `PENDING` | None | None | Registration mode, metric prefix, and outcome vocabulary require product-owner decisions. | Approve the metric exposure and fixed-label policy. |
| 5 | [Release and compatibility contract](release-compatibility.md) | `PROPOSED` | `DRAFT` | `PENDING` | None | None | Initial version and supported Go/Caddy ranges are undecided. | Select the release maturity and supported version ranges. |
| 6 | [CI verification policy](ci-verification-policy.md) | `PROPOSED` | `DRAFT` | `PENDING` | None | Current tests and vet passed at the observed revision; local lint was unavailable. | Coverage, vulnerability-outage, required-check, and integration cadence policies are undecided. | Approve the required-check and coverage policy. |

## Resume protocol

When pausing work:

1. Set the affected feature to its evidence-backed state.
2. Record the full observed revision and, only after successful final proof, the verified revision.
3. Replace the feature row's implementation and verification evidence with concise command or test results.
4. Name any blocker and who or what can resolve it.
5. Leave exactly one bounded next action for the current focus.

When resuming work:

1. Compare `Observed revision` with `git rev-parse HEAD`.
2. Inspect the current worktree and the selected feature specification.
3. Re-run stale direct evidence before advancing the state.
4. Continue only with the recorded next safe action, or update this index if repository evidence invalidates it.

## Completion rule

A feature may be marked `DONE` only when all of its acceptance criteria have direct proof, required checks pass on the final revision, and the recorded observed and verified revisions are identical. `DONE` does not by itself mean merged, deployed, released, or product-owner accepted.
