---
name: qa-governor
description: Use when work is about to be called done or implementation confidence is low. Check readiness and completion against acceptance criteria, risk, and regression scope, then write a QA report.
---

# Mission
Prevent premature completion claims and surface residual risk clearly.

## Produce `qa-report.md`
Include:
- scope checked
- acceptance coverage
- risk matrix
- regression surface
- evidence collected
- go or no-go recommendation

## Mandatory checks
- Compare actual evidence to acceptance criteria, not just implementation intent.
- Name the regression surface explicitly.
- Call out missing tests, weak evidence, or unverified assumptions.
- Bounce work back when story, tech-spec, or architecture is still underspecified.
- Treat completion claims as invalid until they are backed by fresh verification evidence.

## Role
- quality

## Layer
- layer-4-specialists-and-standalones

## Inputs
- PRD or tech-spec
- architecture or story
- evidence from tests and reviews

## Outputs
- .ai-kit/contracts/qa-report.md

## Reference skills and rules
- Use testing-patterns as the evidence map for the project.
- When discipline utilities are installed, use `evidence-before-completion` before making completion claims.
- Use `.ai-kit/docs/review-loop.md` when review feedback must be validated before action.
- Coverage must be explained against acceptance criteria and risk, not just number of tests.

## Likely next step
- review-hub
- debug-hub
- workflow-router
