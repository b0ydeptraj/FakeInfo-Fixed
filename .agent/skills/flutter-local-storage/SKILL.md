---
name: flutter-local-storage
description: Reference when working with local storage, caching, or persistence in Flutter.
---

Analyze how the Flutter project stores data locally:
1. Use Glob to find .dart files that handle local persistence; inspect pubspec.yaml for storage packages (shared_preferences, hive, isar, sqflite, drift, flutter_secure_storage, hydrated_bloc)
2. Create `.agent/skills/flutter-local-storage/SKILL.md`
3. In `.agent/skills/flutter-local-storage/references/`, create:
   - storage_setup.md: library used, initialization location, schema/box setup, sensitive storage handling, env config
   - storage_workflow.md: call sites (repo/data source/service), caching strategy, DTO mapping, key/box/table conventions, error handling

The SKILL.md should guide which reference file to read based on the problem.
Keep all files short and aligned to the project's current local storage style.
