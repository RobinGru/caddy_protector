# Feature plan

Status: Draft — product-owner approval is required before implementation planning.

Implementation progress and the next resumable action are tracked in [STATUS.md](STATUS.md).

This directory splits the repository improvement plan into independently testable capabilities. Each specification defines observable obligations and deliberately avoids prescribing implementation structure.

## Priority order

1. [Outbound request safety](outbound-request-safety.md) — prevent redirects from bypassing configured URL security boundaries or disclosing the Cap secret.
2. [Caddy integration verification](caddy-integration-verification.md) — prove the module works in a real Caddy build, request chain, and configuration reload.
3. [Verification abuse resilience](verification-abuse-resilience.md) — bound abusive traffic to the public verification endpoint without blocking normal users unexpectedly.
4. [Operational metrics](operational-metrics.md) — expose low-cardinality signals for challenges, verification, filtering, dependency health, and refresh freshness.
5. [Release and compatibility contract](release-compatibility.md) — provide versioned installation and an explicit support policy.
6. [CI verification policy](ci-verification-policy.md) — preserve existing evidence while reducing redundant execution and making coverage regression visible.

## Cross-feature sequencing

- Outbound request safety is the first implementation candidate because current redirects can escape the URL policy and a `307` or `308` Cap redirect can resend secret-bearing request content.
- Caddy integration verification should precede changes that affect module lifecycle, directive ordering, or reload behavior.
- Abuse resilience requires product decisions about limits and denial behavior before implementation planning.
- Metrics should use the final outcome vocabulary from outbound safety and abuse resilience.
- Release and CI work can proceed independently after their respective policy decisions are approved.

## Non-feature engineering follow-up

A behavior-preserving split of `caddyprotector.go` into focused internal files may improve maintainability after the higher-priority behavior changes. It must preserve public Go types, JSON fields, Caddyfile directives, defaults, logging semantics, and lifecycle behavior. This is intentionally not a feature specification because it has no intended user-visible behavior change.

## Shared constraints

- Existing Caddyfile and JSON configuration remain backward compatible unless a specification explicitly states otherwise.
- Tokens, cookies, Cap secrets, full query strings, and sensitive headers must not appear in logs, metrics labels, or test artifacts.
- Existing request-filter precedence remains unchanged unless separately approved.
- Security and dependency failures fail closed where access authorization depends on the failed operation.
- Every specification remains a draft until reviewed and approved by the product owner.
