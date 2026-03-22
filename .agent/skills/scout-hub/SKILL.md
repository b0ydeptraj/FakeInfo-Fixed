---
name: scout-hub
description: Use when the repo area is unfamiliar, stale, or likely to drift from existing assumptions. Reconnoiter the codebase and refresh living references before planning, debugging, or review work continues.
---

# Mission
Gather the minimum reliable context the next lane needs so nobody plans or fixes from a false mental model.

## Mandatory behavior
1. Refresh `project-context.md` when architecture, tooling, or domain constraints are unclear.
2. Refresh only the reference files actually relevant to the active lane.
3. Add file paths, commands, or modules whenever possible.
4. If a failure is being investigated, start `investigation-notes.md` with reproduction steps and evidence.

## Output contract
Name exactly what became clearer, what is still unknown, and which hub or specialist should use the refreshed context next.

## Role
- recon-hub

## Layer
- layer-2-workflow-hubs

## Inputs
- repo tree and relevant files
- .ai-kit/contracts/project-context.md
- .ai-kit/state/workflow-state.md

## Outputs
- .ai-kit/contracts/project-context.md
- .ai-kit/references/*.md as needed
- .ai-kit/contracts/investigation-notes.md when the work starts from a failure

## Reference skills and rules
- Use project-architecture, dependency-management, api-integration, data-persistence, and testing-patterns as living references.
- Prefer concrete file paths, commands, and entrypoints over summaries.
- When the problem starts from a failure, capture findings in investigation-notes.

## Likely next step
- plan-hub
- debug-hub
- review-hub
- workflow-router
