# REST API Versioning & Deprecation Policy

This document describes the API versioning strategy, deprecation response headers, migration guidelines, and OpenAPI specifications implemented for the SecureAuth system.

---

## 1. Versioning Architecture

All active production API endpoints reside under the `/api/v1/` directory structure:

- `/api/v1/profile.php` — User profile retrieval and updates.
- `/api/v1/logs.php` — Security audit logs inspection.
- `/api/v1/keys.php` — Scoped API key generation and revocation.
- `/api/v1/export_user_data.php` — GDPR compliance data export.
- `/api/v1/delete_account.php` — User account deletion.
- `/api/v1/csp_report.php` — CSP violation report receiver.
- `/api/v1/openapi.json` — Complete OpenAPI 3.0 specification.

---

## 2. Deprecation Policy & Headers

To ensure legacy API consumers are not broken without warning, legacy unversioned `/api/*.php` endpoints act as proxies to `/api/v1/*.php` and append standard HTTP deprecation headers:

```http
HTTP/1.1 200 OK
Deprecation: true
Link: </api/v1/profile.php>; rel="successor-version"
Sunset: 2027-01-01
```

### Migration Steps for API Consumers:
1. Update endpoint URLs from `/api/endpoint.php` to `/api/v1/endpoint.php`.
2. Provide `X-API-Key: sk_live_...` or `Authorization: Bearer <key>` headers for non-session API requests.
3. Review schema validation definitions in [`api/v1/openapi.json`](file:///c:/Users/LAKSHMANAN/Desktop/secure%20login&%20session/api/v1/openapi.json).
