# Outbound request safety

## Capability and actor

The capability protects operators and their network when `caddy_protector` contacts a configured Cap service, IP-list source, or country database source. The primary actor is the Caddy operator who supplies an outbound URL; the trigger is an initial load, periodic refresh, or token verification.

## Scope and dependencies

In scope:

- redirects from `cap_api_url`, `whitelist_url`, `blacklist_url`, and `country_url`;
- transport security across every followed request;
- protection of `cap_secret_key` and verification tokens;
- deterministic failure behavior when a redirect is disallowed;
- initial loads and refreshes.

Out of scope:

- proving that an allowed remote service is trustworthy;
- DNS rebinding policy beyond the approved address rules;
- generic proxy configuration;
- rate limiting the inbound verification endpoint.

The capability depends on URL validation, outbound HTTP behavior, and existing refresh failure semantics.

## Behavior and rules

- **R1:** A configured URL is not considered safe merely because its first request URL is valid; every redirect target must satisfy the applicable policy.
- **R2:** Cap verification must not forward secret-bearing request content to a different origin.
- **R3:** Cap verification must not downgrade from HTTPS to HTTP. Loopback HTTP remains valid only when it is the originally configured development origin.
- **R4:** List and country-data redirects may be followed only while every target remains an allowed HTTP(S) destination under the approved network policy.
- **R5:** Disallowed redirects fail the current operation and expose a diagnostic that identifies the source kind and rejection reason without exposing credentials or sensitive request content.
- **R6:** A failed periodic refresh retains the last successfully loaded list or database.
- **R7:** A failed initial load prevents provisioning when that source is required by the active configuration.
- **R8:** Redirect chains are bounded and redirect loops fail without hanging.

## Permissions and data

The operator may configure remote sources through the existing configuration interfaces. Remote servers may return data or redirects but cannot authorize a destination outside the configured policy.

Sensitive data includes `cap_secret_key`, verification tokens, signed return states, and internal destination details. Secret-bearing content must be sent only to the approved Cap verification origin and must not be included in errors or logs.

## States and edge cases

- Direct success without redirect.
- Allowed same-origin redirect.
- Cross-origin Cap redirect: denied before resending the request body.
- HTTPS-to-HTTP redirect: denied.
- Redirect to loopback, private, link-local, or otherwise disallowed network space: behavior requires the network-policy decision below.
- Malformed or relative redirect target that cannot be resolved safely: denied.
- Redirect loop or excessive chain: terminal failure for the operation.
- Refresh failure after prior success: stale data remains active and failure is observable.
- Initial required-source failure: provisioning fails.
- Concurrent requests during refresh: continue using the last complete data snapshot.

## Acceptance criteria

- **AC1:** Given an HTTPS Cap origin, when verification receives a `307` or `308` redirect to another origin, then verification fails and the redirected origin receives neither the secret nor token.
- **AC2:** Given an HTTPS Cap origin, when verification redirects to HTTP, then verification fails with a non-sensitive diagnostic.
- **AC3:** Given a remote list or country source, when any redirect target violates the approved URL and address policy, then the load fails before reading data from that target.
- **AC4:** Given an allowed redirect chain within the approved policy and redirect limit, when the final response is valid, then the operation succeeds normally.
- **AC5:** Given a redirect loop or chain beyond the limit, when an outbound operation runs, then it terminates within the configured request deadline and reports a redirect failure.
- **AC6:** Given a successful prior refresh, when a later redirect is rejected, then requests continue to use the prior snapshot and the refresh failure is observable.
- **AC7:** Given no prior snapshot for a required configured source, when its redirect is rejected during provisioning, then provisioning fails.
- **AC8:** Given any redirect failure, when logs and returned errors are inspected, then they contain no Cap secret, verification token, signed state, or remote response body containing those values.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1, R4 | AC3, AC4 | Redirect-target tests for each source kind |
| R2 | AC1, AC8 | Two-server test recording redirected requests |
| R3 | AC2 | HTTPS-to-HTTP redirect test |
| R5 | AC2, AC3, AC8 | Error and captured-log assertions |
| R6 | AC6 | Refresh test with prior snapshot |
| R7 | AC7 | Provisioning failure test |
| R8 | AC5 | Loop and maximum-chain tests with deadline |

## Assumptions and blockers

Observed: current configured URLs are validated, while standard HTTP clients follow redirects automatically.

Approved product decisions:

1. List and MMDB sources may redirect across origins when every target satisfies the approved network policy.
2. HTTPS destinations resolving to loopback, private, link-local, or other non-public addresses are not allowed. HTTP remains valid only for the originally configured loopback development origin.
3. The maximum permitted redirect count is three.

## Implementation plan

1. Use a shared outbound HTTP client that validates every redirect target and resolved address.
2. Permit Cap redirects only to the original HTTPS origin; permit list and country redirects across origins only under the approved policy.
3. Add focused tests for rejected redirects, permitted chains, redirect bounds, and retained refresh snapshots.

## Handoff state

DONE — direct tests cover all acceptance criteria, and `go test ./...`, `go vet ./...`, and `git diff --check HEAD^ HEAD` passed on `01b3eafee0ead24f4dfa85185b6a88d3374b01d8`.
