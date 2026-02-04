---
name: code-review
description: Use before claiming completion, when receiving feedback, or when performing structured code review. Includes verification gates.
---

Analyze project's code review and verification patterns:

1. Find CI/CD config, pre-commit hooks, linting config, test config
2. Create `.agent/skills/code-review/SKILL.md` with:

# Code Review Skill

## Core Principle
Technical correctness over social comfort. Evidence before claims.

## Review Focus Areas
1. Architecture & Design - separation of concerns, module boundaries, patterns
2. Code Quality - readability, naming, complexity, duplication
3. Security & Dependencies - auth, input validation, vulnerable deps
4. Performance & Scalability - hot paths, caching, async patterns
5. Testing Quality - meaningful assertions, coverage of edge cases
6. Documentation & API - README, API changes, breaking changes

## Context Gathering Checklist
- Read README, CONTRIBUTING, ARCHITECTURE if present
- Identify patterns in similar modules
- Note critical domains (auth, payments, data integrity)
- Check lint/test/type-check commands

## Receiving Feedback Protocol
READ -> UNDERSTAND -> VERIFY -> EVALUATE -> RESPOND -> IMPLEMENT
- No performative agreement
- Ask clarifying questions if unclear
- Verify technically before implementing external feedback

## Requesting Review Protocol
- Request review after major changes or complex fixes
- Provide context (what changed, why, risks)
- Include verification evidence

## Verification Gates (IRON LAW)
Identify command -> run -> read output -> verify -> claim with evidence
Claims requiring evidence:
- Tests pass
- Build succeeds
- Bug fixed
- Requirements met

## Issue Prioritization
- CRITICAL: security, data loss, production crash
- HIGH: performance regressions, broken error handling
- MEDIUM: maintainability, missing tests
- LOW: style, minor cleanups

## Project-Specific Checks
- Required linters/formatters
- Required test coverage
- Type checking requirements
