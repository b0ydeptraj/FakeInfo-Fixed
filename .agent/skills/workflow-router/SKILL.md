---
name: workflow-router
description: Use when a request arrives, the user asks what to do next, or scope or complexity is unclear. Route a request through the right delivery track, choose the active orchestrator or hub, and keep workflow-state current.
---

# Mission
Act as the routing kernel for the whole system: choose the track, choose the active lane, and make the next move explicit.

## Mandatory routing procedure
1. Read `.ai-kit/contracts/project-context.md` and `.ai-kit/state/workflow-state.md` if they exist.
2. Score the request on five axes: ambiguity, breadth of change, architecture risk, operational risk, and coordination cost.
3. Classify complexity:
   - `L0`: single bug or tiny refactor
   - `L1`: small feature or bug cluster
   - `L2`: multi-component feature slice
   - `L3`: product or platform change with design trade-offs
   - `L4`: enterprise, compliance, or scale-sensitive work
4. Choose track:
   - `L0-L1` -> quick-flow
   - `L2-L3` -> product-flow
   - `L4` -> enterprise-flow
5. Choose the layer-1 entrypoint:
   - use `bootstrap` if state, context, or artifacts are missing
   - use `cook` for one active request in one lane
   - use `team` if more than one lane, owner, or branch of work must be coordinated
6. Choose the first layer-2 hub:
   - `scout-hub` when the codebase area is unclear
   - `plan-hub` when planning artifacts are missing or stale
   - `debug-hub` when the request starts from a failure or regression
7. Update `.ai-kit/state/workflow-state.md` with the chosen track, orchestrator, hub, exact next skill, and any blockers.

## Escalation rules
Escalate immediately when:
- a small fix changes contracts, schemas, APIs, or infrastructure
- acceptance criteria are unclear or disputed
- multiple bounded contexts are touched
- rollout, migration, security, or compliance risk appears

## Output contract
Never end with vague advice. Always name the next skill, the artifact it should create or update, and what evidence is still missing.

## Role
- routing-kernel

## Layer
- layer-1-orchestrators

## Inputs
- user request
- .ai-kit/contracts/project-context.md (if present)
- .ai-kit/state/workflow-state.md (if present)
- .ai-kit/state/team-board.md (if present)

## Outputs
- .ai-kit/state/workflow-state.md
- .ai-kit/contracts/tech-spec.md or product-brief.md kickoff
- .ai-kit/state/team-board.md when parallel lanes are needed

## Reference skills and rules
- Prefer existing project-context over assumptions.
- Escalate from quick-flow to product-flow whenever hidden complexity appears.
- Hand off to bootstrap when base artifacts are missing, to cook for a single request, and to team when multiple lanes must move in parallel.

## Likely next step
- bootstrap
- cook
- team
- scout-hub
- plan-hub
- debug-hub
