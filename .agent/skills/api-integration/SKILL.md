---
name: api-integration
description: Use when building or changing API clients, webhooks, endpoints, or network-facing code. Document external service integration patterns, clients, auth, retries, and error handling.
---

# Mission
Make network-facing behavior predictable so changes to API code do not become reliability surprises.

## Produce `.ai-kit/references/api-integration.md`
Cover:
- clients, transports, and endpoints
- authentication and secret handling
- retry, timeout, and idempotency rules
- request and response patterns
- error mapping and recovery
- testing and mocking approach

## Working rules
- Name client wrappers, service classes, or endpoint modules directly.
- Include where auth is injected and how secrets are sourced.
- Explain how the code handles network failures, partial failures, and upstream rate limits.
- Note what should be mocked versus tested against a real service.

## Role
- integration-support

## Layer
- layer-4-specialists-and-standalones

## Inputs
- HTTP or RPC client code
- settings or secret config
- test or mock code

## Outputs
- .ai-kit/references/api-integration.md

## Reference skills and rules
- Prefer concrete service names, client classes, and endpoint groups over generic summaries.
- Make retries, timeouts, idempotency, and error translation explicit.

## Likely next step
- architect
- developer
- qa-governor
- review-hub
