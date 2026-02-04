---
name: flutter-dependency-injection
description: Reference when creating new cubits, repositories, services, or understanding how dependencies are wired in the Flutter project.
---

Analyze how the Flutter project manages dependency injection (DI):
1. Use Glob to find related .dart files
2. Inspect pubspec.yaml for DI packages (get_it, injectable, riverpod, provider, flutter_bloc, kiwi, get)
3. Locate DI setup entry points (main.dart, app.dart, bootstrap.dart, locator.dart, di.dart, injection.dart)
4. Detect DI style:
   - Service Locator (GetIt)
   - Code generation DI (injectable)
   - Provider-based DI (Provider, Riverpod)
5. Identify patterns:
   - Module registration structure (core vs feature)
   - Singletons vs factories
   - Environment-based registration (dev/prod)

Create `.agent/skills/flutter-dependency-injection/SKILL.md` with:
1. Detected DI library + style
2. Where registration happens (file paths)
3. How a new service/repository should be registered (short steps)
4. Common conventions found (naming, scopes)

Keep the SKILL.md short and concise, only write the 4 points above.
