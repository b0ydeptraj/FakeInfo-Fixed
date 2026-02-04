---
name: flutter-project-architecture
description: Reference this skill when creating new features or understanding the Flutter layer organization and data flow patterns.
---

Analyze the Flutter project's architecture and folder structure then create flutter-project-architecture skill.

Follow this instruction:
1. Use Glob to find all .dart files
2. Identify the architectural pattern:
   - Clean Architecture (data/domain/presentation)
   - Feature-first organization
   - Layer-first organization
   - MVVM, MVC, or other patterns
3. Create `.agent/skills/flutter-project-architecture/SKILL.md` with:
   1. Actual layer structure the project is using
   2. Actual code flow from UI layer to data layer
   3. Key modules and their responsibilities

Keep the SKILL.md short and concise, only write the 3 points above.
