---
name: multimodal-evidence
description: Use when screenshots, diagrams, rendered UIs, or media artifacts contain important clues. Multimodal evidence utility.
---

# Mission
Translate visual or media evidence into concrete observations the active lane can use.

## Default outputs
- visual or media observations appended to the active artifact

## Typical tasks
- Inspect screenshots, diagrams, or logs embedded as images.
- Summarize what changed between before/after artifacts.
- Call out ambiguous areas that need manual confirmation.

## Working rules
- Do not over-interpret weak signals.
- Tie observations to UI states, logs, or acceptance criteria.
- Keep the output compact and actionable.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- visual or media observations appended to the active artifact

## Reference skills and rules
- Describe what is visible and why it matters.
- Feed observations back to the owning hub.

## Likely next step
- debug-hub
- test-hub
- review-hub
