---
name: bootstrap
description: Use when starting a repo lane, after major structure changes, or whenever workflow-state or project-context is missing or stale. Initialize or refresh the shared Relay-kit runtime before a new lane begins.
---

# Mission
Prepare the runtime so later steps have an authoritative baseline instead of relying on chat memory.

## Mandatory setup
1. Ensure `.ai-kit/state/workflow-state.md` exists and records the current request.
2. Ensure `.ai-kit/contracts/project-context.md` exists. If facts are missing, create a skeletal version with explicit unknowns.
3. If the request is likely to branch into more than one lane, create or refresh `.ai-kit/state/team-board.md`.
4. Record which artifacts already exist and which ones must be refreshed.
5. If the repo area is not well understood, route next to `scout-hub`.

## Guardrails
- Bootstrap does not do deep planning.
- Bootstrap does not declare work ready; it only makes later work safer.
- When in doubt, prefer creating the minimal state needed to hand off cleanly.

## Role
- session-bootstrap

## Layer
- layer-1-orchestrators

## Inputs
- repo root
- .ai-kit/ runtime folders if present
- current request

## Outputs
- .ai-kit/state/workflow-state.md
- .ai-kit/contracts/project-context.md
- .ai-kit/state/team-board.md when parallel work is expected

## Reference skills and rules
- Prefer lightweight initialization over speculative planning.
- If the codebase is unfamiliar, route immediately to scout-hub after bootstrapping.
- Do not invent project-context facts; mark unknowns and hand off to scout-hub.

## Likely next step
- workflow-router
- scout-hub
- cook
- team
