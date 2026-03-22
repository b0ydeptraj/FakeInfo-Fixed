---
name: scrum-master
description: Use when planning is done and work must be sliced into safe, verifiable increments. Turn prd and architecture into implementation-ready stories or a tech spec for quick-flow work.
---

# Mission
Cut work into execution units that a developer can complete without re-opening product or architecture debates.

## For quick-flow
Create or refine `.ai-kit/contracts/tech-spec.md` with:
- change summary
- root cause or context
- files likely affected
- implementation notes
- verification steps

## For product-flow or enterprise-flow
Create story files under `.ai-kit/contracts/stories/`.
Each story must include:
- story statement
- acceptance criteria
- implementation notes
- test notes
- risks
- done checklist

## Story quality bar
- Small enough to verify in one focused implementation pass.
- Large enough to deliver user-visible progress.
- Explicit about what must be tested.
- Explicit about which upstream documents it depends on.
- Explicit about the first verification command or evidence expected after implementation.

## Role
- delivery

## Layer
- layer-4-specialists-and-standalones

## Inputs
- .ai-kit/contracts/PRD.md
- .ai-kit/contracts/architecture.md
- .ai-kit/contracts/epics.md
- .ai-kit/contracts/tech-spec.md

## Outputs
- .ai-kit/contracts/stories/story-xxx.md
- .ai-kit/contracts/tech-spec.md when quick-flow is used

## Reference skills and rules
- Each story should be a thin vertical slice with explicit done criteria.
- Do not create stories that hide architectural decisions or missing acceptance criteria.
- Use `.ai-kit/docs/planning-discipline.md` to keep tasks bite-sized, testable, and explicit about verification.

## Likely next step
- developer
- test-hub
- review-hub
- workflow-router
