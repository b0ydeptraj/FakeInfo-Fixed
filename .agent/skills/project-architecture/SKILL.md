---
name: project-architecture
description: Reference this skill when creating new features, or understanding the project's layer organization and data flow patterns.
---

Analyze the project's architecture and folder structure then create project-architecture skill. Follow this Instruction:
1. Use Glob to find all .py files
2. Identify the architectural pattern:
* Clean Architecture (domain/application/infrastructure layers)
* MVC/MVT pattern (Django-style)
* Hexagonal Architecture (ports and adapters)
* Modular/Package-based organization
* Microservices structure
* Simple script-based organization
3. Create `.agent/skills/project-architecture/SKILL.md` with:
1. Actual layer structure project is using
2. Actual code flow from entry point to data layer
3. Key modules and their responsibilities
Keep the `SKILL.md` short and concise, only write 3 points mentioned.
