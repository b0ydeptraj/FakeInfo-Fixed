# folder-structure

Recommended runtime layout:

- `.ai-kit/contracts/` -> stable artifact contracts shared across roles and hubs
- `.ai-kit/state/` -> workflow-state, team-board, lane-registry, handoff-log, and other runtime breadcrumbs
- `.ai-kit/references/` -> living support references for architecture, APIs, persistence, testing, security, observability, and performance
- `.ai-kit/docs/` -> topology docs, migration notes, gating rules, and orchestration rules
- `.claude/skills/`, `.agent/skills/`, `.codex/skills/` -> adapter-specific runtime skill folders
- `.relay-kit-prompts/` -> preferred generic prompt output path
- `.python-kit-prompts/` -> compatibility alias for generic prompt output during one migration cycle
- `relay_kit_legacy.py` -> canonical legacy generator for analysis/template kits
- `python_kit_legacy.py` -> compatibility alias for one migration cycle
- `relay_kit.py` -> current Relay-kit v3 entrypoint that adds orchestration, routing, hubs, utility providers, contracts, and gating
- `python_kit.py` -> compatibility alias for one migration cycle
