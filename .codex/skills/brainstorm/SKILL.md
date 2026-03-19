---
name: brainstorm
description: generate and compare implementation options before planning or coding. use when there are multiple plausible architectures, tradeoffs between simplicity and extensibility, ui or data-flow design choices, or uncertainty about the best technical direction.
---

# Brainstorm

## Overview
Explore plausible solution paths before locking in a plan.

## Workflow
1. Clarify the decision to be made.
2. Generate 2-4 viable technical approaches.
3. Compare tradeoffs across complexity, risk, maintainability, performance, and implementation effort.
4. Recommend a default path.
5. Hand off to `plan` with the chosen direction and rejected alternatives.

## Output Pattern
- Decision
- Options
- Tradeoffs
- Recommended path
- Next step

## Rules
- Prefer concrete engineering tradeoffs over generic ideation.
- Avoid endless option generation; converge on a recommendation.
- Use this skill to unblock `plan`, not to replace it.
