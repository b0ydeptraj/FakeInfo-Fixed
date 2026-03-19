---
description: Build an execution plan for complex coding work before implementation
argument-hint: [task]
---
Ultrathink.

Create a concise but high-confidence execution plan for:

$ARGUMENTS

## Responsibilities
- Clarify the engineering objective.
- Identify constraints, non-goals, and risky assumptions.
- Inspect relevant files, modules, configs, and tests before proposing edits.
- Prefer existing patterns and abstractions already present in the codebase.
- For complex work, write or update `.ai-kit/state/plan.md`.

## Use These Skills As Needed
- `scout` for codebase mapping and impact analysis.
- `docs-seeker` for framework or library guidance.
- `repomix` for repo packaging or large-context inspection.
- `brainstorm` when there are multiple viable designs or tradeoffs.
- `context-engineering` to compress or structure large findings.
- `mermaidjs-v11` if an architecture diagram would clarify the plan.

## Plan Output Must Include
1. Objective
2. Relevant files and why they matter
3. Constraints and non-goals
4. Assumptions and unknowns
5. Step-by-step implementation plan
6. Validation plan
7. Risks and rollback notes

Do not start broad implementation until the plan is coherent and evidence-backed.
