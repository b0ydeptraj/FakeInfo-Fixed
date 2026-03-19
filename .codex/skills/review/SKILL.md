---
name: review
description: perform final engineering review on completed code changes. use after implementation and validation to inspect regressions, edge cases, maintainability, type safety, test coverage, and readiness to ship or merge.
---

# Review

## Overview
Provide the last quality gate before the task is considered complete.

## Workflow
1. Inspect the changed files and surrounding code paths.
2. Use `scout` if additional codebase context is needed for edge cases.
3. Check for correctness, regressions, missing tests, poor abstractions, and risky assumptions.
4. Confirm that validation was appropriate for the scope.
5. Return a concise verdict with required follow-ups, if any.

## Review Checklist
- Correctness
- Regression risk
- Edge cases
- Readability and maintainability
- Type and interface safety
- Test sufficiency
- Ship readiness

## Output Pattern
- Verdict
- Key findings
- Required follow-ups
- Optional improvements

## Rules
- Prioritize material issues over style nitpicks.
- Distinguish blockers from suggestions.
- Recommend looping back to `fix` or `validate` when needed.
