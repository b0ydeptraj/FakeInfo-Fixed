---
name: flutter-test-writing
description: Reference when writing Flutter tests or matching existing test patterns.
---

Analyze the Flutter project's testing approach:
1. Inspect pubspec.yaml for test libraries (flutter_test, test, mocktail, mockito, bloc_test, integration_test, golden_toolkit)
2. Use Glob to locate test folders and naming conventions (test/, integration_test/, *_test.dart)
3. Detect testing types (unit, widget, integration, golden)
4. Identify patterns (mocking, setup/teardown, helpers like pumpApp)

Create `.agent/skills/flutter-test-writing/SKILL.md` with:
1. Folder structure and naming rules
2. How widget/repository/view-model tests are written
3. How to mock dependencies (DI + mocks)
4. Common assertion style and naming conventions
5. How to test loading/error/success states

Keep the file short and aligned to the project's current testing style.
