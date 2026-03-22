---
name: dependency-management
description: Use when adding packages, updating libraries, or diagnosing environment drift. Capture dependency policy, lockfile usage, environment setup, and safe add-or-upgrade rules.
---

# Mission
Prevent dependency changes from becoming hidden architecture or release risk.

## Produce `.ai-kit/references/dependency-management.md`
Cover:
- package manager and lockfiles
- environment and toolchain setup
- version pinning and upgrade policy
- dev vs prod dependencies
- how to add a new dependency
- known dependency risks

## Working rules
- Name the exact files that define dependencies.
- Note whether the team uses strict pinning, ranges, extras, or split requirement sets.
- Explain how contributors should add, upgrade, and verify dependencies without drifting from CI.
- Flag packages that are security-sensitive, hard to upgrade, or tightly coupled to runtime behavior.

## Role
- build-support

## Layer
- layer-4-specialists-and-standalones

## Inputs
- package metadata files
- lockfiles
- toolchain config
- CI setup if present

## Outputs
- .ai-kit/references/dependency-management.md

## Reference skills and rules
- Record both the official package manager and what contributors actually use day to day.
- Make transitive risk and pinning policy explicit.

## Likely next step
- architect
- developer
- qa-governor
- review-hub
