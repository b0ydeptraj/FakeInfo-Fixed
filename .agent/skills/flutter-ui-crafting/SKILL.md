---
name: flutter-ui-crafting
description: Guide for building Flutter UI components, screens, navigation, translation, assets, forms, and shared widgets.
---

Analyze how the Flutter project builds widgets and screens:
1. Use Glob to find view, screen, widget .dart files
2. Create `.agent/skills/flutter-ui-crafting/SKILL.md`
3. In `.agent/skills/flutter-ui-crafting/references/`, create:
   - theme.md: how Text styles, colors, spacing, and backgrounds are applied in real widgets
   - navigation.md: navigation package and real navigation patterns
   - translation.md: i18n files location and how translation keys are used (skip if not used)
   - assets.md: asset setup and real usage (Image.asset, SvgPicture, cached images, etc.)
   - form.md: validation, submit flow, focus handling, error display (skip if not used)
   - common_widget.md: shared components and when to use them (1 line each)

The SKILL.md should guide which reference file to read based on the problem.
Keep all files short and aligned to the project's current UI style.
