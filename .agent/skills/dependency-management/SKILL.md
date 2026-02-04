---
name: dependency-management
description: Reference when adding packages, understanding dependencies, or setting up development environment.
---

Analyze how the project manages dependencies:
1. Find files: `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `poetry.lock`
2. Identify approach: pip, Poetry, Pipenv, PDM, Hatch
3. Detect virtual environment: venv, virtualenv, conda, Docker
4. Identify patterns: Dev vs prod, version pinning, extras

Create `.agent/skills/dependency-management/SKILL.md` with:
1. Detected dependency manager + style
2. Where dependencies are defined (file paths)
3. How to add a new dependency (short steps)
4. Common conventions (dev/prod split, pinning)
