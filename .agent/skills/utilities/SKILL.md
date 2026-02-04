---
name: utilities
description: Reference when working with utilities or checking existing functions before creating new ones.
---

Analyze the project's utility functions and helpers:
1. Find `.py` files with reusable logic:
   - Utility classes: StringUtils, DateUtils, Validator, Formatter
   - Decorators: @retry, @cache, @timer, custom decorators
   - Context managers: with statement implementations
   - Custom exceptions
2. Create `.agent/skills/utilities/SKILL.md` with references folder:
   - List each utility class/function with 1-line description
   - Group by category (string, date, validation, etc.)

The SKILL.md guides to correct reference file.
