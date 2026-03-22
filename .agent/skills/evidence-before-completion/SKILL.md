---
name: evidence-before-completion
description: Use when a hub or specialist is about to say work is done, fixed, or ready. Completion-evidence utility.
---

# Mission
Stop premature completion claims by forcing a claim-to-evidence check.

## Default outputs
- fresh verification evidence and claim checks appended to qa-report, workflow-state, or the active artifact

## Typical tasks
- List the exact claims being made.
- Name the command, artifact, or output that proves each claim.
- Reject claims that are not backed by fresh evidence.

## Working rules
- Confidence is not evidence.
- Partial verification is not completion.
- If evidence is stale or missing, route back to testing or debugging instead of approving the lane.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- fresh verification evidence and claim checks appended to qa-report, workflow-state, or the active artifact

## Reference skills and rules
- No completion claims without fresh verification output.
- Match every claim to the command or evidence that proves it.

## Likely next step
- test-hub
- qa-governor
- review-hub
