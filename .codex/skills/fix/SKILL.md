---
name: fix
description: implement code changes after planning or debugging. use when chatgpt already has a clear implementation direction and needs to modify code through the best-matched domain expert, keeping diffs minimal, aligned with existing patterns, and validated afterward.
---

# Fix

## Overview
Apply the implementation changes through the most relevant domain expert.

## Routing Hints
- React, component logic, hooks, client UI -> `react-expert`
- Next.js app/router/server actions -> `nextjs-expert`
- TypeScript typing and interfaces -> `typescript-expert`
- API, services, backend logic -> `backend-development` or the closest backend specialist
- auth/session/security flows -> `authentication-expert`
- database/schema/query layers -> `database-expert`, `prisma-expert`, `postgres-expert`, or `mongodb-expert`
- infrastructure, deployment, ci -> `devops-expert`

## Workflow
1. Consume the handoff from `plan` or `debug`.
2. Choose the narrowest domain expert capable of the change.
3. Apply the smallest coherent diff.
4. Preserve existing conventions unless the task explicitly changes them.
5. Hand off to `validate` immediately after edits.

## Rules
- Do not mix unrelated cleanup into the same pass.
- Prefer reuse of existing abstractions over introducing new patterns.
- If the fix expands in scope, hand back to `plan`.
