---
name: scout
description: inspect and map an existing codebase before changes. use when chatgpt needs to locate relevant files, trace dependencies, understand current architecture, identify affected surfaces, or prepare context for planning, debugging, implementation, or review.
---

# Scout

## Overview
Map the codebase and gather the minimum context needed for confident changes.

## Workflow
1. Identify entrypoints, core modules, data flow, and boundaries relevant to the request.
2. Locate the files most likely to require edits.
3. Trace dependencies, imports, call paths, and related tests.
4. Summarize the current implementation shape and likely blast radius.
5. Hand off findings to `plan`, `debug`, `fix`, or `review`.

## What To Look For
- file ownership of the feature or bug
- shared utilities and abstractions
- config, environment, and framework conventions
- existing tests covering the area
- adjacent code that may also need updates

## Output Pattern
Return concise structured findings:
- Key files
- Current behavior
- Dependencies and risks
- Recommended next skill

## Rules
- Prefer evidence from actual code paths over guesses.
- Highlight hidden coupling and likely regression surfaces.
- Do not rewrite architecture notes; focus on what helps the next step execute.
