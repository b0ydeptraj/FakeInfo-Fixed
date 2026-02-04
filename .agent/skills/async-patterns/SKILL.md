---
name: async-patterns
description: Reference when implementing async operations, background tasks, or concurrency patterns.
---

Analyze how the project handles asynchronous operations:
1. Find `.py` files with async/await, threading, multiprocessing
2. Check for: asyncio, aiohttp, celery, rq, dramatiq, concurrent.futures
3. Create `.agent/skills/async-patterns/SKILL.md` with references folder containing:
   - async_setup.md: Event loop, task queue config, worker pools
   - async_workflow.md: Async function structure, concurrency control, error handling

The SKILL.md guides when to use async vs sync patterns.
