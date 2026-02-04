---
name: flutter-utilities
description: Reference when working with Flutter utility helpers or checking existing utilities before creating new ones.
---

Analyze how the Flutter project creates and reuses non-UI helpers (utilities, extensions, constants):
1. Use Glob to find .dart files with reusable logic (StringUtils, DateUtils, Validator, Formatter), extensions, or mixins
2. Create `.agent/skills/flutter-utilities/SKILL.md`
3. In `.agent/skills/flutter-utilities/references/`, create files per category and list utility classes/functions with 1-line descriptions

The SKILL.md should guide which reference file to read based on the problem.
Keep all files short and aligned to the project's current utilities.
