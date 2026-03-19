---
name: plan
description: create execution plans for non-trivial coding work. use when a task spans multiple files, requires architecture or state-flow decisions, involves refactors or migrations, or needs a step-by-step implementation and validation plan before code changes begin.
---

# Plan

## Overview
Create a concise but actionable execution plan before implementation.

## Use This Skill To Produce
- implementation steps
- affected files and why they matter
- assumptions and unknowns
- validation strategy
- risks and rollback notes

## Workflow
1. Restate the engineering objective in implementation terms.
2. Identify constraints, non-goals, and likely impact surface.
3. If code context is incomplete, invoke `scout`.
4. If multiple approaches are plausible, invoke `brainstorm` first.
5. Produce a step-by-step plan with explicit verification steps.
6. Recommend the next skill: usually `fix`, `debug`, or `validate`.

## Output Pattern
Prefer this structure:
- Objective
- Constraints
- Relevant files
- Plan
- Validation
- Risks
- Next step

## Rules
- Keep the plan short enough to execute, but specific enough to prevent thrashing.
- Do not drift into implementation unless the user asked for immediate execution.
- Update the plan when new evidence invalidates earlier assumptions.
