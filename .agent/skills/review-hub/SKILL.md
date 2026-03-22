---
name: review-hub
description: Use when artifacts disagree or before final completion claims. Check alignment across requirements, architecture, implementation, and quality evidence, then decide whether to accept, re-slice, debug, or re-plan.
---

# Mission
Make completion a deliberate alignment check, not just a feeling that enough has happened.

## Mandatory checks
- Do requirements, architecture, and implementation still describe the same change?
- Does quality evidence actually cover the promised behavior and regression surface?
- Is the active lane done, or is it merely unblocked enough to continue elsewhere?

## Output contract
End with one explicit verdict:
- go forward,
- bounce to planning,
- bounce to debugging,
- bounce to implementation,
- or hold for missing evidence.

## Review handling discipline
- Verify external review feedback against the codebase before accepting it.
- Prefer one review item at a time when feedback changes code or requirements.
- If the lane is complete, route through branch-completion discipline before treating it as finished.

## Role
- review-hub

## Layer
- layer-2-workflow-hubs

## Inputs
- active artifacts
- qa-report if present
- workflow-state

## Outputs
- updated workflow-state
- go/no-go review verdict
- specific bounce-back path when misalignment exists

## Reference skills and rules
- Review-hub is the mesh junction: it may send work back to plan, debug, fix, or test.
- Do not hide disagreement between artifacts; name it and route accordingly.
- Use `.ai-kit/docs/review-loop.md` and `.ai-kit/docs/branch-completion.md` for review handling and end-of-branch discipline.

## Likely next step
- plan-hub
- debug-hub
- fix-hub
- test-hub
- workflow-router
