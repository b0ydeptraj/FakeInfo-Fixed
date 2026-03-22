---
name: handoff-context
description: Use when the next skill needs a tighter, more relevant context handoff than the current artifact already provides. Context-pack utility.
---

# Mission
Prepare the smallest complete context pack for the next handoff.

## Default outputs
- focused context pack notes added to workflow-state, story, or handoff-log
- an explicit include/exclude list for the receiving skill

## Typical tasks
- Select the minimum set of files, artifacts, and rules the receiving skill actually needs.
- State why each included item matters.
- Name what was deliberately excluded and why it is safe to ignore for now.
- Write a short receiving-skill brief so the next handoff starts cleanly.

## Working rules
- Context quality beats context quantity.
- Use authoritative artifacts over memory.
- Update handoff-log when the receiving skill changes.
- Stop when the receiving skill can act without reopening the whole repo or replaying the whole chat.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- focused context pack notes added to workflow-state, story, or handoff-log
- an explicit include/exclude list for the receiving skill

## Reference skills and rules
- Minimize irrelevant context.
- Package only what the receiving skill needs to act safely.

## Likely next step
- workflow-router
- team
- cook
- developer
