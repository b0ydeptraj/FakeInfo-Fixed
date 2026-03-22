---
name: repo-map
description: Use when a hub needs a quick dependency map, file tree slice, or entrypoint overview before acting. Repo-map utility.
---

# Mission
Produce a compact map of the code area the lane is about to touch.

## Default outputs
- repo map notes appended to project-context or architecture
- a short read-first file list for the next skill

## Typical tasks
- Scope the map to the area the lane is actually about to touch.
- List key entrypoints, modules, and dependency direction.
- Highlight hotspots, choke points, or ownership boundaries.
- Name the first files the next skill should read instead of dumping the whole tree.

## Working rules
- Prefer repo-relative paths, modules, and boundaries over prose-heavy summaries.
- Keep the map small enough for the next skill to use immediately.
- If ownership is fuzzy, say so explicitly instead of inventing structure.
- Stop once the next skill can navigate without another broad repo walk.

## Role
- utility-provider

## Layer
- layer-3-utility-providers

## Inputs
- active hub or orchestrator request
- current authoritative artifact
- only the evidence relevant to this pass

## Outputs
- repo map notes appended to project-context or architecture
- a short read-first file list for the next skill

## Reference skills and rules
- Good for unfamiliar areas and dependency direction.
- Use it to orient the lane, not to replace design thinking.

## Likely next step
- scout-hub
- plan-hub
- review-hub
