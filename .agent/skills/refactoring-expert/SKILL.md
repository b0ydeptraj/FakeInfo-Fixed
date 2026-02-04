---
name: refactoring-expert
description: Use proactively when encountering duplicated code, long methods, complex conditionals, or other code smells.
---

Analyze project's code patterns and create refactoring skill:

1. Detect project structure (tests, linters, type checking)
2. Create `.agent/skills/refactoring-expert/SKILL.md` with:

## Safe Refactoring Process
1. Ensure tests exist (create if missing)
2. Make one small refactor at a time
3. Run tests and linting
4. Commit if green
5. Repeat

## Code Smell Categories

### Composing Methods
- Long Method -> Extract Method
- Duplicated Code -> Extract and reuse
- Complex Conditionals -> Decompose Conditional

### Moving Features Between Objects
- Feature Envy -> Move Method/Field
- Inappropriate Intimacy -> Extract Class
- Message Chains -> Hide Delegate

### Organizing Data
- Primitive Obsession -> Replace with Domain Object
- Data Clumps -> Introduce Parameter Object
- Magic Numbers -> Replace with Named Constant

### Simplifying Conditionals
- Nested if/else -> Guard Clauses
- Switch on type -> Replace with Polymorphism
- Null checks everywhere -> Null Object

### Making Method Calls Simpler
- Long parameter list -> Introduce Parameter Object
- Flag parameters -> Split into separate methods

### Dealing with Generalization
- Duplicate code in subclasses -> Pull Up Method
- Refused Bequest -> Replace Inheritance with Delegation

## Validation Steps
After each refactor:
1. Run tests: pytest
2. Check linting: ruff check . (or flake8)
3. Verify types: mypy . (if used)

## Metrics to Track
- Cyclomatic complexity: <10
- Lines per method: <20
- Parameters per method: <=3
