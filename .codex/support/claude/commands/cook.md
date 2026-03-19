---
description: Orchestrate a full coding workflow from plan to review
argument-hint: [task]
---
Ultrathink.

Execute the following workflow for this task:

$ARGUMENTS

## Goal
Act as the top-level orchestrator for implementation work. Coordinate the workflow instead of jumping straight into code.

## Required Flow
1. Start with `plan` to define approach, constraints, risks, and validation strategy.
2. Use `scout` to inspect the current codebase, impacted files, architecture boundaries, and reuse opportunities.
3. If there is a bug, ambiguity, or failure signal, invoke `debug` before changing code.
4. Use `fix` to implement the chosen approach through the most relevant specialist skills.
5. Use `validate` to run the narrowest useful checks first, then broader checks when warranted.
6. Use `review` to catch regressions, edge cases, typing risks, and maintainability issues.
7. Summarize the result briefly with changed files, validation performed, and any remaining risks.

## Routing Rules
- Prefer workflow hubs over calling domain experts directly.
- Use utility skills to gather evidence, not to own strategy.
- Reuse existing abstractions and patterns before introducing new ones.
- Keep diffs focused on the requested task.
- Do not auto-commit, auto-push, or create documentation unless explicitly requested.

## State
For complex work, maintain:
- `.ai-kit/state/plan.md`
- `.ai-kit/state/routes.json`
- `.ai-kit/state/findings.md`

## Handoff Contract
When invoking another hub or specialist, include:
- Objective
- Current state
- Evidence
- Affected files
- Constraints
- Assumptions
- Proposed next step
- Validation plan
- Risks
