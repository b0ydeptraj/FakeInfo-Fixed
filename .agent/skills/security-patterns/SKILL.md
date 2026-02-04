---
name: security-patterns
description: Use when implementing authentication, authorization, input validation, or security features. Covers OWASP Top 10 mitigations.
---

Analyze project's security patterns:

1. Find auth/security related code
2. Check for: authentication, authorization, input validation, secrets handling
3. Create `.agent/skills/security-patterns/SKILL.md` with:

## Input Validation
- Validate ALL user input (never trust client)
- Use allowlists over denylists
- Parameterized queries (prevent SQL injection)
- Sanitize for XSS if rendering HTML

## Authentication
- Password hashing: Use Argon2id or bcrypt (NEVER MD5/SHA1)
- JWT: Short expiry, secure storage, proper validation
- OAuth 2.1: Use PKCE for all flows
- MFA: Implement where possible

## Authorization
- Principle of least privilege
- RBAC (Role-Based Access Control) pattern
- Check permissions at every layer
- Never rely on client-side checks alone

## Secrets Management
- Never commit secrets to git
- Use environment variables or secret managers
- Rotate secrets regularly
- Different secrets per environment

## Common Vulnerabilities (OWASP Top 10)
1. Broken Access Control → Check auth at every endpoint
2. Injection → Parameterized queries
3. Cryptographic Failures → Use strong algorithms
4. Security Misconfiguration → Review defaults
5. SSRF → Validate URLs, allowlist domains

## Security Headers
- Content-Security-Policy
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Strict-Transport-Security
