---
name: cook
description: orchestrate complex coding work across planning, codebase scouting, debugging, implementation, validation, and review. use when the user wants to implement a feature, execute a multi-step change, or run an end-to-end coding workflow instead of manually invoking separate specialist skills.
---

# Cook

## Overview
Run the default end-to-end coding workflow. Act as the primary orchestrator for non-trivial software tasks.

## Workflow
1. Determine whether the task is feature work, bug fixing, refactor, or review-driven follow-up.
2. Invoke `plan` for multi-step work or ambiguous implementation requests.
3. Invoke `scout` to map the codebase, affected files, dependencies, and likely impact surface.
4. If the task is a bug or failing behavior, invoke `debug` before editing code.
5. Invoke `fix` to make the implementation changes through the best-matched domain expert.
6. Invoke `validate` to run the narrowest useful verification for the changed surface.
7. Invoke `review` to check regressions, edge cases, and code quality before finishing.

## Routing Rules
- Use `plan` whenever the change touches multiple files, interfaces, flows, or systems.
- Use `debug` before `fix` when the root cause is unclear.
- Use `brainstorm` before `plan` when multiple viable designs or tradeoffs exist.
- Use `validate` and `review` before considering the task done.

## Handoff Contract
Whenever delegating, pass:
- Objective
- Current constraints
- Relevant files or suspected areas
- Evidence already collected
- Desired output for the next skill

## Completion Rules
Do not stop after planning or editing alone. The default completion path is:
`plan -> scout -> debug/fix -> validate -> review`

Skip only the steps that are clearly unnecessary for a very small task.
