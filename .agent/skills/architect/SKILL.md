---
name: architect
description: Use when a prd exists or when a change could alter module boundaries, data flow, security, or operations. Convert requirements into an implementation-ready architecture that fits the existing codebase.
---

# Mission
Make downstream implementation safer by turning requirements into explicit technical constraints and decisions.

## Produce `architecture.md`
Include:
- current-system constraints
- proposed design
- module boundaries
- data flow and integrations
- operational concerns
- trade-offs and ADR notes
- implementation readiness verdict

## Mandatory behavior
- Reuse existing patterns unless there is a documented reason not to.
- Name interfaces, boundaries, and ownership explicitly.
- State how observability, rollback, and failure handling will work for risky changes.
- Flag any requirement that cannot be satisfied within the current architecture without upstream scope negotiation.

## Role
- solutioning

## Layer
- layer-4-specialists-and-standalones

## Inputs
- .ai-kit/contracts/PRD.md
- .ai-kit/contracts/project-context.md
- existing support skills and references

## Outputs
- .ai-kit/contracts/architecture.md

## Reference skills and rules
- Mirror the existing codebase before inventing new patterns.
- Pull in project-architecture, dependency-management, api-integration, data-persistence, security-patterns, performance-optimization, and logging-observability when relevant.
- Architecture must include a readiness verdict, not just diagrams or aspirations.

## Likely next step
- scrum-master
- review-hub
- plan-hub
- workflow-router
