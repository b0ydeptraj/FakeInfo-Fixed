---
name: sequential-thinking
description: Use when a hub needs structured thought without changing ownership. Stepwise reasoning utility for debugging, planning, or decomposition.
---

# Mission
Turn a messy question into a short sequence of evidence-backed steps.

## Default outputs
- ordered reasoning steps added to investigation-notes or the active artifact

## Typical tasks
- Decompose the problem into checkpoints.
- Identify what must be known before acting.
- Recommend the next most informative test or observation.

## Working rules
- Keep the sequence short and testable.
- Tie each step to an artifact or evidence source.
- Do not claim completion for the lane.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- ordered reasoning steps added to investigation-notes or the active artifact

## Reference skills and rules
- Break work into explicit steps and checkpoints.
- Reasoning should support a decision, not become the decision owner.

## Likely next step
- debug-hub
- plan-hub
- fix-hub
