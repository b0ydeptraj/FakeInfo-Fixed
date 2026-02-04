---
name: sequential-thinking
description: Use for complex problems requiring step-by-step reasoning with ability to revise, branch, or dynamically adjust scope.
---

Create a sequential thinking skill for complex problem-solving:

Create `.agent/skills/sequential-thinking/SKILL.md` with:

## When to Use
- Multi-step analysis or design
- Debugging complex issues
- Architecture decisions
- Refactoring planning
- Problem with initially unclear scope

## The Process

### Structure Each Thought
```
Thought 1 of N: "Problem involves X. Need to understand Y first."
Thought 2 of N: "Analyzing Y reveals Z pattern."
Thought 3 (revision of 1): "Actually, core issue is W, not X."
Thought 4 of N: "Solution approach: ..."
```

### Core Capabilities
- **Iterative reasoning**: Break into sequential steps
- **Dynamic scope**: Adjust total thoughts as understanding evolves
- **Revision tracking**: Can modify previous conclusions
- **Branch exploration**: Explore alternative paths from any point

### When to Revise
- New information contradicts earlier assumption
- Better approach discovered
- Original scope was wrong

### When to Branch
- Multiple viable approaches exist
- Need to explore alternatives before committing
- Risk/benefit analysis needed

## Tips
- Start with rough estimate, refine as you progress
- Express uncertainty explicitly
- Adjust scope freely - progress visibility matters
- Stop when conclusion reached
