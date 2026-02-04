---
name: logging-observability
description: Use when implementing logging, error tracking, or monitoring. Covers structured logging, metrics, and tracing patterns.
---

Analyze project's logging and monitoring:

1. Find logging setup, error tracking, monitoring config
2. Create `.agent/skills/logging-observability/SKILL.md` with:

## Logging Levels
- DEBUG: Detailed diagnostic info (dev only)
- INFO: General operational events
- WARNING: Something unexpected but handled
- ERROR: Error that prevented operation
- CRITICAL: System-wide failure

## Structured Logging Pattern
```python
import logging
import json

logger = logging.getLogger(__name__)

# Include context in every log
logger.info("User action", extra={
    "user_id": user.id,
    "action": "login",
    "ip": request.ip
})
```

## What to Log
- Request/response (sanitized, no secrets)
- User actions (audit trail)
- Errors with full context
- Performance metrics (duration, count)
- External service calls

## What NOT to Log
- Passwords, tokens, API keys
- Full credit card numbers
- Personal data (unless required)
- High-frequency events (will flood logs)

## Error Tracking Integration
- Sentry / Rollbar / Bugsnag
- Include: stack trace, user context, environment
- Group similar errors
- Alert on new/increased errors

## Metrics & Monitoring
- Application metrics: request count, latency, error rate
- Business metrics: signups, purchases, conversions
- Infrastructure: CPU, memory, disk

## Tracing (Distributed Systems)
- Correlation ID across services
- OpenTelemetry for standardization
- Trace requests through entire flow
