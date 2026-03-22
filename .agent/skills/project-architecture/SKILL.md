---
name: project-architecture
description: Use when designing a change, reviewing architectural drift, or implementing code in an unfamiliar area. Analyze the current codebase shape and maintain a living architecture reference.
---

# Mission
Build and maintain an accurate map of the current architecture so downstream roles stop guessing.

## Produce `.ai-kit/references/project-architecture.md`
Cover:
- entry points and execution flow
- layer or package structure
- module responsibilities
- dependency direction and boundaries
- architecture drift and hotspots
- files to mirror when adding new work

## Working rules
- Prefer observed runtime or code flow over folder names alone.
- Name boundaries explicitly: controllers, services, repositories, adapters, domain logic, jobs, or scripts.
- Flag any mismatch between the intended architecture and what the code actually does.
- Add file paths whenever the reference names a pattern or module.

## Role
- architecture-support

## Layer
- layer-4-specialists-and-standalones

## Inputs
- repository tree
- .ai-kit/contracts/project-context.md
- .ai-kit/contracts/architecture.md when available

## Outputs
- .ai-kit/references/project-architecture.md

## Reference skills and rules
- Document what the codebase actually does today, not what the team intended six months ago.
- Include concrete file paths, entrypoints, and dependency direction.

## Likely next step
- architect
- developer
- review-hub
