# handoff-log

## Handoff entries
| From | To | Lane | Trigger | Artifact touched | Evidence linked | Expected return condition |
|---|---|---|---|---|---|---|
| workflow-router | cook | primary | route selected | workflow-state | TBD | hub chosen |
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## Rules
- Every non-trivial handoff should update this log before the receiving skill starts work.
- Link to the authoritative artifact, not only a chat summary.
- If a handoff changes scope or ownership, update `workflow-state.md` and `lane-registry.md` in the same pass.
