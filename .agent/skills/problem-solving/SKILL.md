---
name: problem-solving
description: Use when a hub needs hypotheses, trade-offs, or resolution paths grounded in current evidence. Option-generation and root-cause utility.
---

# Mission
Turn evidence into plausible options and ranked next moves.

## Default outputs
- options, hypotheses, and trade-offs appended to the active artifact

## Typical tasks
- Generate root-cause hypotheses.
- Compare implementation or mitigation options.
- Call out the cheapest validating experiment.

## Working rules
- Ground every option in evidence already collected.
- State uncertainty instead of bluffing.
- Recommend escalation if the issue is really a planning problem.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- options, hypotheses, and trade-offs appended to the active artifact

## Reference skills and rules
- Root cause beats guess-and-patch.
- Surface trade-offs before implementation starts.

## Likely next step
- debug-hub
- plan-hub
- review-hub
