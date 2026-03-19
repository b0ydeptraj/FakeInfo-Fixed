---
description: Review a completed or in-progress change for regressions and quality risks
argument-hint: [change or task]
---
Ultrathink.

Review this work:

$ARGUMENTS

## Responsibilities
- Check correctness against the original objective.
- Look for edge cases, regression risk, typing issues, accessibility impact, and maintainability problems.
- Verify that the solution reused existing patterns where appropriate.
- Flag over-engineering, unnecessary churn, and missing validation.
- Prefer focused, high-signal findings over long commentary.

## Use These Skills As Needed
- `scout` to inspect adjacent code paths and hidden impact surface.
- `validate` to confirm tests, checks, and manual validation are sufficient.
- `typescript-type-expert` for strict typing and inference issues.
- `accessibility-expert` for UI/UX accessibility risks.
- `git-expert` if diff structure or commit hygiene affects reviewability.

## Review Output Must Include
- What looks correct
- High-priority issues
- Medium-risk concerns
- Missing tests or validation
- Recommended follow-up actions

Keep the review concise, actionable, and engineering-focused.
