---
name: debug
description: diagnose coding failures and identify root causes before fixes. use when there is an error, regression, failing test, unexpected runtime behavior, broken ui flow, or uncertain bug source requiring evidence gathering and structured debugging.
---

# Debug

## Overview
Identify the most likely root cause and the smallest reliable path to a fix.

## Workflow
1. Reproduce or restate the failing behavior as concretely as possible.
2. Invoke `scout` if the relevant code paths are not yet mapped.
3. Gather evidence from code, logs, stack traces, tests, and runtime behavior.
4. Use utility skills when appropriate:
   - `docs-seeker` for framework or library behavior
   - `chrome-devtools` for browser-side issues
   - `mcp-management` when MCP-backed tooling is needed
5. Narrow the issue to a root-cause hypothesis.
6. Hand off to `fix` with evidence, likely cause, and affected files.

## Output Pattern
- Symptom
- Reproduction or observed evidence
- Root-cause hypothesis
- Affected files
- Recommended fix direction

## Rules
- Prefer reproducible evidence over intuition.
- Do not jump directly to code edits when the cause is still uncertain.
- Call out competing hypotheses if the evidence is incomplete.
