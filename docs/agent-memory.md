# Repository memory

This repository provides the `caddy_protector` Caddy HTTP middleware. GitHub Actions checks pull requests before they can merge into `main`.

## Index

- [Required check names](#required-check-names)

## Required check names

The external GitHub ruleset [Protect main](https://github.com/RobinGru/caddy_protector/rules/20201130) requires exact check names from GitHub Actions. The test job includes the Go matrix version in its name. Updating that version changes the reported check name, but does not update the ruleset automatically; a successful workflow can therefore leave merging blocked by an obsolete expected check.

When changing the test matrix version or another required job name, reconcile the corresponding ruleset entry with the actual reported check and preserve its GitHub Actions source. Verify both workflow success and the PR merge requirements.
