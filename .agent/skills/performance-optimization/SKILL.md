---
name: performance-optimization
description: Use when optimizing performance, profiling, or fixing bottlenecks. Always profile first before optimizing.
---

Analyze project's performance patterns:

1. Find performance-related code (caching, queries, profiling)
2. Create `.agent/skills/performance-optimization/SKILL.md` with:

## Profiling First
ALWAYS profile before optimizing:
- cProfile / profile for CPU
- memory_profiler for memory
- py-spy for live profiling
- line_profiler for line-by-line

## Common Python Optimizations

### Algorithm & Data Structures
- Use sets for membership tests (O(1) vs O(n))
- Use generators for large sequences
- Choose right data structure (dict vs list)

### Caching
- functools.lru_cache for pure functions
- Redis/Memcached for distributed caching
- HTTP caching headers for APIs
- Query result caching

### Database
- N+1 query problem → Use eager loading
- Add indexes for frequently queried columns
- Connection pooling
- Query analysis with EXPLAIN

### Async / Concurrency
- asyncio for I/O-bound
- multiprocessing for CPU-bound
- ThreadPoolExecutor for blocking I/O
- Avoid premature async (adds complexity)

### Memory
- Use __slots__ for many small objects
- Generators instead of lists
- Process large files in chunks
- del large objects when done

## Performance Checklist
- [ ] Profiled to find actual bottleneck
- [ ] Optimized hot path only
- [ ] Measured improvement
- [ ] No regression in functionality
- [ ] Code still readable
