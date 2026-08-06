# Operational metrics

## Capability and actor

Operators can observe protection outcomes and dependency health without parsing logs or exposing high-cardinality or sensitive data. The trigger is normal request handling, verification, and source refresh activity.

## Scope and dependencies

In scope:

- challenge, allow, block, and verification outcomes;
- Cap verification duration and dependency failures;
- list and country-database refresh outcomes and freshness;
- stable, bounded metric dimensions.

Out of scope:

- distributed tracing;
- dashboards and alert deployment;
- recording individual client identities, URLs, tokens, or rules;
- changing access decisions.

The capability depends on Caddy's supported metrics integration and stable outcome names from neighboring capabilities.

## Behavior and rules

- **R1:** Operators can count challenge responses, allowed requests, and blocked requests by a bounded reason category.
- **R2:** Operators can count Cap verification outcomes and observe verification duration.
- **R3:** Operators can observe refresh success, failure, and the age of the last successful snapshot for each source kind.
- **R4:** Metric names and labels remain stable within a compatible release line.
- **R5:** Labels never contain client IPs, hostnames supplied by requests, paths, query strings, headers, cookies, tokens, secrets, country codes from arbitrary input, or configured source URLs.
- **R6:** Metrics collection must not alter request decisions and must add only bounded work per event.
- **R7:** Disabled or unused source types do not report misleading successful freshness.

## Permissions and data

Metrics are available only through Caddy's configured metrics exposure. This capability does not itself make a metrics endpoint public. All recorded dimensions must come from a fixed vocabulary controlled by the module.

## States and edge cases

- Metrics integration enabled or unavailable.
- Challenge, cookie allow, IP allow, and upstream continuation.
- Request-rule, blacklist, and country-rule block.
- Verification success, invalid token, local validation failure, local limit, Cap transport failure, and Cap protocol failure.
- Initial source load, successful refresh, failed refresh with retained data, and never-successful source.
- Configuration reload without duplicate collectors or stale series ownership.

## Acceptance criteria

- **AC1:** Given representative request outcomes, when metrics are collected, then each outcome increments exactly one documented request counter category.
- **AC2:** Given Cap verification success, denial, and dependency failure, when metrics are collected, then each appears under a distinct fixed outcome and duration is observed only for attempted Cap calls.
- **AC3:** Given a successful source load followed by a failed refresh, when metrics are read, then the failure count increases and freshness continues from the last successful load.
- **AC4:** Given a configured source that has never loaded successfully, when metrics are read, then it is distinguishable from a fresh source.
- **AC5:** Given requests containing unique IPs, paths, queries, headers, tokens, and cookies, when metric label values are enumerated, then none of those values appear.
- **AC6:** Given a configuration reload, when metrics are collected afterward, then registration succeeds without duplicate-collector errors and each event is counted once.
- **AC7:** Given metrics support is unavailable or disabled, when the module serves requests, then request behavior remains unchanged.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1 | AC1 | Outcome table test |
| R2 | AC2 | Recording verifier and histogram assertions |
| R3, R7 | AC3, AC4 | Refresh state tests |
| R4 | AC1, AC2 | Documented metric schema snapshot |
| R5 | AC5 | High-cardinality sentinel test |
| R6 | AC6, AC7 | Reload and disabled-metrics tests |

## Assumptions and blockers

Product decisions required:

1. Whether metrics are always registered when Caddy metrics are available or require explicit module configuration.
2. The public metric prefix and exact fixed outcome vocabulary.
3. Whether configured source kinds are distinguishable only as `allowlist`, `blacklist`, and `country`, without URL labels.

## Handoff state

PRODUCT DECISION REQUIRED
