---
name: api-integration
description: Reference when implementing API calls, creating endpoints, handling network errors, or working with external services.
---

Analyze how the project communicates with external APIs:
1. Find `.py` files handling HTTP requests
2. Check for: requests, httpx, aiohttp, urllib3, grpcio, graphql-core
3. Create `.agent/skills/api-integration/SKILL.md` with references folder containing:
   - api_setup.md: Base URL, authentication, retry logic, timeouts
   - api_workflow.md: Service classes, request/response patterns, error handling

The SKILL.md guides which reference file to read based on the problem.
