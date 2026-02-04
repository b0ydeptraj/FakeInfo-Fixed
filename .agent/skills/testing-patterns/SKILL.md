---
name: testing-patterns
description: Reference when writing tests, creating fixtures, or understanding testing patterns.
---

Analyze the project's testing approach:
1. Check for: pytest, unittest, hypothesis, pytest-mock, pytest-cov, faker, factory_boy
2. Find test folders: tests/, test/, *_test.py, test_*.py, conftest.py
3. Detect testing types: Unit, Integration, E2E, Property-based
4. Identify patterns: Fixtures, mocking, test data factories

Create `.agent/skills/testing-patterns/SKILL.md` with:
- Folder structure and naming rules
- How tests are organized
- How to mock dependencies
- Common fixture patterns
- How to test async code (if applicable)

Skip if no tests exist.
