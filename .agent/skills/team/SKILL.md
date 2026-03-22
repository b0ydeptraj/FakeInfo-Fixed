---
name: team
description: Use when work must proceed in parallel, when planning and implementation overlap, or when one lane is blocked and another can move. Coordinate multi-lane or multi-session work without letting agents step on each other.
---

# Mission
Coordinate parallel work while preserving one authoritative source of truth for each artifact.

## Mandatory behavior
1. Maintain `.ai-kit/state/team-board.md` with lanes, owners, active artifacts, blockers, and merge order.
2. Split work only when lanes are independent enough to avoid editing the same artifact section at the same time.
3. Use `cook` to drive each active lane, but keep final merge and priority decisions here.
4. If one lane uncovers architecture or scope drift, update workflow-state and notify all affected lanes.
5. Park lanes that are blocked instead of letting them thrash.
6. Record lock scope and handoff status whenever a lane changes ownership or pauses.

## Do not do this
- Do not let two lanes silently diverge on the same acceptance criteria.
- Do not keep lane state only in memory.
- Do not parallelize before a quick scout when the codebase area is unfamiliar.

## Role
- meta-orchestrator

## Layer
- layer-1-orchestrators

## Inputs
- .ai-kit/state/workflow-state.md
- .ai-kit/state/team-board.md
- active artifacts and blockers

## Outputs
- .ai-kit/state/team-board.md
- .ai-kit/state/workflow-state.md

## Reference skills and rules
- Shared artifacts beat chat summaries; update the artifact before handing off.
- Assign one owner skill per lane and name merge order explicitly.
- Use cook inside a lane, not as a replacement for team.
- Use `.ai-kit/docs/parallel-execution.md` to decide when work is independent enough to split safely.

## Likely next step
- cook
- plan-hub
- scout-hub
- debug-hub
- review-hub
