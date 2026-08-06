# Caddy integration verification

## Capability and actor

Maintainers can verify that the module operates correctly in a real custom Caddy build rather than only through isolated handlers and Caddyfile adaptation. The trigger is a repository verification run in local development or CI.

## Scope and dependencies

In scope:

- custom Caddy build containing the module;
- Caddyfile loading and directive registration;
- middleware ordering and upstream continuation;
- challenge and verification requests through a running Caddy instance;
- configuration reload and cleanup of background resources.

Out of scope:

- browser automation for solving a real Cap challenge;
- deployment infrastructure;
- performance benchmarking;
- compatibility with unapproved Caddy versions.

The capability depends on `xcaddy` or an equivalent supported build path and isolated local test services.

## Behavior and rules

- **R1:** The documented example configuration must adapt and start when supplied with valid local test dependencies.
- **R2:** An unverified protected request receives the challenge response and does not reach the upstream.
- **R3:** The verification route is handled by the module and never forwarded upstream.
- **R4:** A valid verification result produces an allow cookie that permits a subsequent protected request.
- **R5:** An allowlisted request reaches the upstream without a challenge.
- **R6:** A blocked request does not reach the upstream.
- **R7:** A valid configuration reload completes without leaving old refresh activity or country-database resources active.
- **R8:** An invalid reload is rejected while the previously active configuration remains serviceable according to Caddy's reload contract.

## Permissions and data

Only test-owned local services and temporary files may be contacted. Test secrets and tokens must be synthetic and must not be uploaded as artifacts. The test harness may start and stop local processes but must not mutate external systems.

## States and edge cases

- Build success or module-registration failure.
- Initial configuration start.
- Challenge response.
- Verification success and denial.
- Upstream continuation.
- Successful reload.
- Rejected reload.
- Process shutdown and cleanup.
- Port collision or missing build prerequisite: explicit test-environment failure, not a product failure.

## Acceptance criteria

- **AC1:** Given a supported toolchain, when the integration build runs, then the resulting Caddy binary lists or loads `http.handlers.caddy_protector`.
- **AC2:** Given a running protected route, when a client without an allow cookie requests it, then it receives the challenge and the upstream records no request.
- **AC3:** Given a valid synthetic Cap response, when a client posts to `verify_path`, then it receives an allow cookie and the upstream records no verification request.
- **AC4:** Given the cookie from AC3, when the client retries the protected route, then the upstream receives exactly one request.
- **AC5:** Given an allowlisted client, when it requests the protected route, then the upstream receives the request without a challenge.
- **AC6:** Given a matching deny rule, when a client requests the protected route, then the upstream receives no request.
- **AC7:** Given an active configuration with refresh workers, when a valid replacement configuration is reloaded, then the new behavior becomes observable and the old workers terminate.
- **AC8:** Given an active valid configuration, when an invalid replacement is submitted, then the reload fails and the prior route remains available.

## Traceability

| Requirement | Acceptance criteria | Planned proof |
| --- | --- | --- |
| R1 | AC1 | Custom binary smoke test |
| R2, R3 | AC2, AC3 | Running Caddy plus recording upstream |
| R4 | AC3, AC4 | Stateful HTTP client test |
| R5, R6 | AC5, AC6 | Configured request cases |
| R7 | AC7 | Reload with observable worker dependency |
| R8 | AC8 | Invalid reload followed by prior-route request |

## Assumptions and blockers

Assumption: CI may install a pinned `xcaddy` version and bind loopback ports. The supported Caddy version range must be established by the release and compatibility contract.

## Handoff state

DONE — direct tests cover all acceptance criteria, and the integration test, tagged static analysis, and commit diff check passed on `e0ad773e272fb5e555b5e896f2de8ba89dda9de5`.
