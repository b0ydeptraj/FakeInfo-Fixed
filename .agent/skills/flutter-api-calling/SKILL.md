---
name: flutter-api-calling
description: Reference when implementing API calls, creating new endpoints, handling network errors, or working with remote data sources in Flutter.
---

Analyze how the Flutter project communicates with APIs:
1. Use Glob to find .dart files that handle networking; inspect pubspec.yaml for packages (dio, http, retrofit, chopper, graphql, json_annotation, freezed)
2. Create `.agent/skills/flutter-api-calling/SKILL.md`
3. In `.agent/skills/flutter-api-calling/references/`, create:
   - api_setup.md: Base URL config, interceptors (auth/logging/retry), timeouts, token storage, refresh flow
   - api_workflow.md: Repository pattern, data sources/services, DTO mapping, error handling strategy

The SKILL.md should guide which reference file to read based on the problem.
Keep all files short and aligned to the project's current API style.
