---
name: flutter-state-management
description: Reference when creating or modifying cubits, states, or understanding how UI communicates with business logic in Flutter.
---

Analyze how the Flutter project manages UI and business state:
1. Use Glob to find state, view model, cubit, bloc, provider, and use-case .dart files
2. Inspect pubspec.yaml for state management packages (flutter_bloc, bloc, riverpod, provider, mobx, get, stacked)
3. Create `.agent/skills/flutter-state-management/SKILL.md`
4. In `.agent/skills/flutter-state-management/references/`, create:
   - state_format.md: state file naming, structure, and state variants (Initial, Loading, etc.)
   - view_model_format.md (or cubit_format.md/provider_format.md): naming, DI into view model, file structure, function patterns
   - add event/use_case files if needed

The SKILL.md should explain how view communicates with view model and how view model talks to repositories/services.
Keep all files short and aligned to the project's current state management style.
