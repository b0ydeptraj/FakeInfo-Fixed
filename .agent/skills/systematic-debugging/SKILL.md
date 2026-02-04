---
name: systematic-debugging
description: Use when encountering ANY bug, test failure, or unexpected behavior. NEVER jump to solutions - always investigate root cause first using 4-phase framework.
---

Analyze project's debugging patterns and create a comprehensive systematic debugging skill:

1. Find logging setup (logging, loguru, structlog), error handling patterns, debug utilities
2. Create `.agent/skills/systematic-debugging/SKILL.md` with THE IRON LAW:

## The 4-Phase Debugging Framework

**NO FIXES WITHOUT ROOT CAUSE INVESTIGATION FIRST**

### Phase 1: Root Cause Investigation
- Read error messages COMPLETELY (stack traces, line numbers)
- Reproduce consistently (exact steps, every time?)
- Check recent changes (git diff, new dependencies)
- For multi-component systems: Add diagnostic logging at EACH boundary
- Trace data flow backward from error to source

### Phase 2: Pattern Analysis
- Find working examples in codebase
- Compare against references (read COMPLETELY, don't skim)
- Identify ALL differences (don't assume "that can't matter")
- Understand dependencies and assumptions

### Phase 3: Hypothesis and Testing
- Form SINGLE hypothesis: "I think X is root cause because Y"
- Make SMALLEST possible change to test
- One variable at a time
- If doesn't work → NEW hypothesis, don't add more fixes

### Phase 4: Implementation
- Create failing test case FIRST
- Implement SINGLE fix addressing root cause
- Verify: test passes, no regression, issue resolved
- If 3+ fixes failed → STOP, question architecture

## Red Flags - STOP and Return to Phase 1
- "Quick fix for now, investigate later"
- "Just try changing X and see"
- "Add multiple changes, run tests"
- Proposing solutions before tracing data flow

## Project-Specific Patterns
- Describe project's logging patterns
- Common error patterns in this codebase
- Where to add debug logs
