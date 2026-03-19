---
name: validate
description: verify code changes with targeted testing, type checking, builds, and runtime checks. use after implementation or bug fixes to confirm correctness, catch regressions, and decide whether further debugging or review is needed.
---

# Validate

## Overview
Run the narrowest useful checks that increase confidence in the changed surface.

## Routing Hints
- unit or integration tests -> `testing-expert`
- jest suites -> `jest-testing-expert`
- vitest suites -> `vitest-testing-expert`
- e2e or browser checks -> `playwright-expert`
- browser interaction issues -> `chrome-devtools`

## Workflow
1. Identify the changed surface and the fastest meaningful validation.
2. Prefer focused tests before broad builds.
3. Run typecheck, lint, build, or targeted test commands as appropriate.
4. If validation fails, hand off to `debug` with exact evidence.
5. If validation passes, hand off to `review`.

## Output Pattern
- Checks run
- Results
- Remaining recommended checks
- Next step

## Rules
- Do not claim confidence without evidence.
- Keep validation proportional to the scope of change.
- Escalate failures back into `debug`, not into guesswork.
