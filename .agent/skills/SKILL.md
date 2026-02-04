---
name: agentic-loop
description: Self-correcting development loop with enforced 4-phase debugging. Use when building features that require iteration until success. Never allows quick fixes - always finds root cause first.
---

You are now in AGENTIC MODE. This is a self-correcting development loop.

Create `.agent/skills/agentic-loop/SKILL.md` with:

## THE AGENTIC LOOP

```
┌─────────────────────────────────────────────────────────────┐
│  1. UNDERSTAND requirement completely                       │
│  2. WRITE code to fulfill requirement                       │
│  3. RUN code/tests                                          │
│  4. ANALYZE results:                                        │
│     ├─ SUCCESS → Go to step 6                               │
│     └─ ERROR → Go to step 5                                 │
│  5. FIX using 4-Phase Framework (see below) → Go to step 3  │
│  6. VERIFY with evidence → REPORT results                   │
└─────────────────────────────────────────────────────────────┘
```

## IRON LAW FOR FIXING

**ABSOLUTELY FORBIDDEN:**
- ❌ Quick/temporary fixes
- ❌ "Just try this and see"
- ❌ Multiple changes at once
- ❌ Fix without understanding root cause
- ❌ Skip writing test for the fix

**MANDATORY 4-PHASE FIX PROCESS:**

### Phase 1: Root Cause Investigation (DO THIS FIRST)
- Read error message COMPLETELY
- Trace data flow backward: Where does bad value come from?
- Check recent changes: git diff, new dependencies
- Add diagnostic logging if needed
- DO NOT propose fix until you understand WHY it broke

### Phase 2: Pattern Analysis
- Find working code in same codebase doing similar thing
- Compare: What's different between working and broken?
- Read documentation/references COMPLETELY, don't skim

### Phase 3: Hypothesis
- Form SINGLE hypothesis: "Root cause is X because Y"
- Test with SMALLEST possible change
- One variable at a time
- If wrong → Back to Phase 1 with new information

### Phase 4: Fix Implementation
- Write failing test FIRST
- Make SINGLE targeted fix
- Run tests
- If 3+ fixes failed → STOP, architecture may be wrong

## VERIFICATION BEFORE CLAIMING SUCCESS

Before saying "done":
1. RUN actual tests (not cached results)
2. READ complete output
3. SHOW evidence: "Tests pass: [output showing 0 failures]"
4. No evidence = Not done

## LOOP TERMINATION

Continue looping until:
- All tests pass with evidence
- User's requirement is met (verified, not assumed)
- Report includes: what was done, what was tested, evidence of success

## ANTI-PATTERNS TO REJECT

If you catch yourself thinking:
- "Quick fix for now" → STOP, find root cause
- "Should work" → STOP, verify first
- "Add multiple changes" → STOP, one at a time
- "Skip the test" → STOP, test is mandatory
