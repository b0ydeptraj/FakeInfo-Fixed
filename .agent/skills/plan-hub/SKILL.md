---
name: plan-hub
description: Use when work is larger than quick-flow or when existing planning artifacts are stale or incomplete. Run the planning chain from brief to prd to architecture to stories without losing context between roles.
---

# Mission
Sequence the planning roles so the lane produces buildable artifacts instead of disconnected documents.

## Mandatory order
- use `analyst` if the brief is missing or stale
- use `pm` if requirements, acceptance criteria, or slice order are missing
- use `architect` if technical boundaries or readiness are unclear
- use `scrum-master` when work must be cut into stories or a quick spec

## Planning gate
Stop and route to `review-hub` when product, architecture, and story artifacts disagree.
Route to `developer` only when the active story or tech-spec is ready for implementation.

## Planning discipline
- Prefer small, verifiable slices over broad task bundles.
- Every story or quick spec should name what will prove it is done.
- If the work spans unrelated subsystems, split the plan before implementation starts.

## Role
- planning-hub

## Layer
- layer-2-workflow-hubs

## Inputs
- workflow-state
- existing brief, prd, architecture, or epics if present
- project-context

## Outputs
- product-brief, PRD, architecture, epics, and stories or tech-spec depending track

## Reference skills and rules
- Call only the roles needed to close the current planning gap.
- Use scout-hub first if the current codebase context is too weak to plan safely.
- Route to review-hub if artifacts disagree with one another.
- Use `.ai-kit/docs/planning-discipline.md` to keep plans artifact-first, bite-sized, and verification-aware.

## Likely next step
- analyst
- pm
- architect
- scrum-master
- developer
- review-hub
