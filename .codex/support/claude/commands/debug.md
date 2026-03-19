---
description: Perform root-cause analysis before fixing a bug or failure
argument-hint: [bug or failure]
---
Ultrathink.

Investigate and isolate the root cause for:

$ARGUMENTS

## Responsibilities
- Reproduce the issue whenever practical.
- Trace the failing path end-to-end.
- Distinguish symptoms from root cause.
- Verify assumptions against actual code, logs, runtime behavior, and docs.
- Prefer evidence, instrumentation, and focused tests over guesswork.
- Leave behind actionable findings that `fix` can implement directly.

## Use These Skills As Needed
- `triage-expert` for structured diagnostic reasoning.
- `docs-seeker` for API, framework, or library semantics.
- `chrome-devtools` for browser-side failures, network issues, rendering bugs, and performance traces.
- `mcp-management` when the best evidence comes from MCP-enabled tools.
- `context-engineering` to condense large findings.

## Output Requirements
Produce a concise debugging handoff containing:
- Observed failure
- Reproduction status
- Root cause hypothesis or confirmed cause
- Evidence
- Impacted files or layers
- Recommended next step for `fix`
- Validation needed after the fix

Do not jump into broad refactors while the cause is still uncertain.
