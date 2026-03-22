---
name: testing-patterns
description: Use when adding tests, updating fixtures, validating regressions, or deciding what proof is enough. Capture how the project tests code, mocks dependencies, and gathers evidence.
---

# Mission
Turn the project test suite into a usable playbook for implementation and quality review.

## Produce `.ai-kit/references/testing-patterns.md`
Cover:
- frameworks and folder rules
- fixture and factory patterns
- mocking and dependency isolation
- async or integration testing rules
- commands for local evidence
- coverage gaps and brittle areas

## Working rules
- Name the real commands contributors should run for fast confidence versus deeper verification.
- Show where fixtures, factories, and mocks live and when each should be preferred.
- Call out unstable tests, heavy integration paths, and areas with weak coverage.
- Tie recommendations back to risk, not just test quantity.

## Role
- quality-support

## Layer
- layer-4-specialists-and-standalones

## Inputs
- test folders
- test config
- fixtures or factories
- CI or local test commands

## Outputs
- .ai-kit/references/testing-patterns.md

## Reference skills and rules
- Explain how to produce evidence locally, not only what frameworks exist.
- Map tests to risk areas and brittle zones where regressions cluster.

## Likely next step
- developer
- qa-governor
- debug-hub
- test-hub
- review-hub
