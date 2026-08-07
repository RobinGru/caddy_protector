# Verification abuse resilience

## Capability and actor

A legitimate browser can complete Cap verification while abusive clients cannot cause unbounded outbound verification traffic through the public `verify_path`. The actors are legitimate clients, abusive clients, operators, and the configured Cap dependency.

## Scope and dependencies

In scope:

- requests to `verify_path`;
- admission limits before outbound Cap verification;
- observable retry behavior;
- bounded state and cleanup;
- interaction with trusted client-IP resolution.

Out of scope:

- general rate limiting for protected upstream routes;
- replacing Cap's own abuse controls;
- user authentication or authorization;
- distributed enforcement unless explicitly approved.

The capability depends on Caddy's trusted proxy configuration and the outbound Cap service.

## Behavior and rules

- **R1:** Existing method, content-type, body-size, token, and signed-state validation occurs before an outbound Cap request whenever possible.
- **R2:** Verification attempts exceeding the approved policy are rejected without contacting Cap.
- **R3:** Rejection communicates a stable HTTP status and retry guidance without revealing whether a supplied token would otherwise be valid.
- **R4:** Normal verification bursts within the approved policy continue to work.
- **R5:** Limiting state has an explicit upper bound and expired entries are removable.
- **R6:** Client identity uses Caddy's trusted client-IP result and does not trust arbitrary forwarding headers directly.
- **R7:** A Cap timeout or dependency failure does not grant access and remains distinguishable operationally from a locally limited request.
- **R8:** Configuration reload and shutdown do not leak limiter activity or retain stale state beyond the approved lifecycle.

## Permissions and data

Any network client may call the public verification route, but only requests admitted by validation and the abuse policy may trigger a Cap request. Client IP addresses are operational security data and must not be exposed through metrics labels. Retention of limiter state must be bounded and documented.

## States and edge cases

- First valid attempt.
- Burst within allowance.
- Limit exceeded.
- Retry after recovery period.
- Malformed request rejected before accounting decision, subject to approved policy.
- Multiple clients behind one address.
- Client address unavailable or malformed.
- Concurrent attempts for the same identity.
- Cap timeout or non-success response.
- Reload and shutdown.
- Multi-instance deployment where local limits are not globally coordinated.

## Acceptance criteria

- **AC1:** Given a malformed or invalidly signed request, when it reaches `verify_path`, then no outbound Cap request is made.
- **AC2:** Given attempts within the approved allowance, when valid requests arrive, then each proceeds to normal Cap verification.
- **AC3:** Given an identity that exceeds the approved allowance, when another valid request arrives, then it receives the approved limited response and Cap receives no corresponding request.
- **AC4:** Given a previously limited identity, when the approved recovery condition is met, then a valid attempt can proceed again.
- **AC5:** Given concurrent attempts, when the allowance is exhausted, then admitted outbound requests never exceed the policy's defined burst behavior.
- **AC6:** Given more distinct identities than the state bound, when limiter state is inspected over time, then memory remains bounded and expired state is reclaimed.
- **AC7:** Given an unavailable Cap service, when an admitted verification is attempted, then access is not granted and the result is observable as dependency failure rather than local limiting.
- **AC8:** Given a spoofed forwarding header from an untrusted peer, when identity is determined, then the spoofed value does not independently select a different limit bucket.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1 | AC1 | Recording Cap server and malformed-request matrix |
| R2, R3 | AC3 | Limit-exhaustion response test |
| R4 | AC2, AC4 | Burst and recovery tests |
| R5 | AC5, AC6 | Concurrent and high-cardinality tests |
| R6 | AC8 | Trusted/untrusted proxy context tests |
| R7 | AC7 | Cap timeout/failure test |
| R8 | AC6 | Lifecycle and cleanup test |

## Assumptions and blockers

Approved product decisions:

1. Limiting is enabled by default.
2. Enforcement is per trusted client IP with a burst of 15 and one recovered attempt every 3 seconds (at most 20 per minute). Rejections use HTTP 429 with `Retry-After`.
3. Malformed requests do not consume allowance; only requests that could reach Cap are admitted to the limiter.
4. Requests without a valid client IP fail closed with HTTP 400 and do not contact Cap.
5. Per-instance enforcement is acceptable and must be documented as not globally coordinated.

## Implementation plan

1. Add a bounded, concurrency-safe per-client token bucket to the verification path after request validation and before Cap verification.
2. Emit a stable 429 response with calculated retry guidance; keep Cap dependency failures distinct.
3. Add focused tests for admission, recovery, concurrency, bounded cleanup, trusted client identity, and lifecycle cleanup.

## Handoff state

DONE — direct tests cover all acceptance criteria, and focused race tests, static analysis, and the commit diff check passed on `d4c959e5f0e27f17797b5f0708db84294c264aef`.
