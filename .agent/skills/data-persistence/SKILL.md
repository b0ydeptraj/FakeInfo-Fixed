---
name: data-persistence
description: Use when touching schemas, repositories, transactions, caches, or data flows. Document storage topology, models, migrations, caching, and consistency rules.
---

# Mission
Make data changes safer by documenting where state lives, how it moves, and what can go wrong.

## Produce `.ai-kit/references/data-persistence.md`
Cover:
- stores and connection points
- schemas, models, and repositories
- migrations and schema evolution
- transactions and consistency
- caching and invalidation
- data risks and rollback notes

## Working rules
- Name concrete stores and frameworks: Postgres, Redis, SQLite, MongoDB, ORM, query builder, and so on.
- Explain who owns writes, reads, cache invalidation, and transaction boundaries.
- Flag destructive migrations, data backfills, and dual-write or consistency hazards.
- Include file paths for models, repositories, migrations, and seed logic when they exist.

## Role
- persistence-support

## Layer
- layer-4-specialists-and-standalones

## Inputs
- model files
- repository or DAO code
- migration files
- cache config if present

## Outputs
- .ai-kit/references/data-persistence.md

## Reference skills and rules
- Cover both primary storage and auxiliary state like caches, queues, or object stores when relevant.
- Document rollback and migration risks, not only happy-path structure.

## Likely next step
- architect
- developer
- qa-governor
- review-hub
