# AGENTS.md

## Language

Always answer the user in German.

Write code, comments, documentation, commits, issues, pull requests, and other repository artifacts in English.


Be concise, explicit, and technically precise.

## Repository Memory

`docs/agent-memory.md` contains durable, repository-specific knowledge that is not obvious from the code or canonical documentation.

Before non-trivial work:
- If the file exists, consult its index and read only the sections relevant to the current task.
- If the file does not exist, create it when the task provides enough verified information to make it useful.
- A newly created file should begin with a brief repository overview, followed by an index of documented topics.

Before finishing, update the file only when the task revealed a verified, durable insight that is likely to prevent future mistakes or repeated investigation.

Do not add assumptions, temporary task details, generic best practices, or information that is already clear from the code or canonical documentation.


## Working Style

- Use the narrowest suitable tool, evidence set, and file scope.
- Expand scope only for demonstrated dependencies, contracts, side effects, callers, or failures.
- Do not recursively inventory the repository unless required.
- Do not print complete files, trees, diffs, or long logs unless requested.
- Do not narrate routine tool use.
- Preserve exact identifiers, commands, numbers, units, conditions, exceptions, and error messages.
- Keep repository artifacts professional.

## Engineering Rules

- The human owns product intent, architecture, review, risk, and irreversible actions.
- Prefer correctness, simplicity, readability, and consistency.
- Make the smallest coherent change.
- Preserve unrelated behavior and existing work.
- Avoid speculative abstractions and unrelated cleanup, formatting, or renaming.
- Do not hide failures with broad catches or silent fallbacks.
- Never weaken tests merely to make them pass.
- Report conflicts between instructions and verified project facts or invariants.

## Skill Use

Use a skill only when its workflow materially improves the task.

- Handle trivial, localized, low-risk changes directly.
- Use the narrowest applicable skill.
- Do not activate skills based on keywords alone.
- Combine skills only when each is independently necessary.

## Verification

Match verification to the change's size and risk.

For every change:

1. Write the change.
2. Re-read the changed range and nearby context.
3. Run the narrowest meaningful check.
4. Extremely compactly report the change and verification.

For large or higher-risk changes, also:

- Read relevant contracts and dependencies before editing.
- Inspect the full diff when multiple files, generated artifacts, lock files, or unrelated changes may be involved.
- Exercise the changed behavior with a focused proof.
- Run broader tests, linting, type checks, or builds only when justified.

For auto-fixable Biome issues:

```sh
rtk npm run lint:fix
rtk npm run lint
```

Never claim a file change, test result, repository status, or memory update without verification.
