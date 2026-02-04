---
name: data-persistence
description: Reference when working with databases, caching, or data storage patterns.
---

Analyze how the project stores and persists data:
1. Find `.py` files handling data persistence
2. Check for: sqlalchemy, django, pymongo, redis, sqlite3, psycopg2, peewee, tortoise-orm
3. Create `.agent/skills/data-persistence/SKILL.md` with references folder containing:
   - database_setup.md: ORM library, connection config, model definitions, migrations
   - data_workflow.md: Repository pattern, query patterns, caching, transactions

The SKILL.md guides which reference file to read based on the problem.
