# OWASP Top 10 Security Vulnerability Mapping (2021/2026 Edition)

This document provides a comprehensive mapping of implemented security controls, verification test results, and recommendations for all 10 OWASP Top 10 security categories for the **Secure Login & Session Management Application**.

---

## OWASP Top 10 Comprehensive Mapping Matrix

| OWASP Category | Applicable / N/A | Current Implemented Protection | Tests & Verifications Performed | Remaining Risk | Recommended Future Improvement |
|---|---|---|---|---|---|
| **A01: Broken Access Control** | `APPLICABLE` | Server-side RBAC (`require_admin()`), object-level authorization (`can_access_user_resource()`), direct URL access blocking, IDOR prevention on profiles & APIs. | Automated regression test suite (`tests/security_regression_test.php`), DAST scan (`scripts/dast_scan.php`). | None (Application layer). | Maintain strict role checks on any future API additions. |
| **A02: Cryptographic Failures** | `APPLICABLE` | `password_hash()` (Argon2id / bcrypt cost 12), authenticated AES-256-GCM encryption at rest (`encrypt_pii()`) for PII, TLS 1.3 HTTPS enforcement, `HttpOnly`/`Secure`/`SameSite=Lax` cookies. | Encryption round-trip unit test, SAST scanner secret check (`scripts/sast_scan.php`). | None. | Periodically rotate `APP_ENCRYPTION_KEY`. |
| **A03: Injection** | `APPLICABLE` | 100% prepared SQL statements with MySQLi parameter binding across all database queries; XSS output escaping with HTML entity encoding (`e()`); CSP `script-src 'self'`. | SAST scanner query parsing, DAST header inspection. | None. | Enforce strict ORM/QueryBuilder if scaling database complexity. |
| **A04: Insecure Design** | `APPLICABLE` | Threat-modeled architecture: mandatory MFA for Admins, Step-Up password re-verification (`require_step_up()`) for sensitive actions, progressive rate-limiting delays. | Synthetic Health Check (`scripts/synthetic_health_check.php`). | None. | Conduct periodic threat modeling during major feature updates. |
| **A05: Security Misconfiguration** | `APPLICABLE` | Production error handler suppressing stack traces (`includes/error_handler.php`), `.htaccess` blocking direct access to `.env`, `.sql`, `.log`, and `backups/`, strict HTTP security headers. | DAST scan testing HTTP 403 / 302 responses and CSP headers. | Server / Web Host misconfigurations. | Enable Cloudflare WAF or AWS WAF at DNS level. |
| **A06: Vulnerable & Outdated Components** | `APPLICABLE` | Minimal external dependencies, standard PHP core libraries (`ext-mysqli`, `ext-openssl`), `composer.json` & `composer.lock` dependency lockfiles. | SAST scanner dependency audit (`composer validate --strict`). | Third-party Google Fonts CDN availability. | Run `composer audit` in CI/CD pipeline on dependency upgrades. |
| **A07: Identification & Auth Failures** | `APPLICABLE` | Multi-Factor Authentication TOTP 2FA (RFC 6238), WebAuthn Passkeys support, session fixation defense (`session_regenerate_id()`), 30-min idle timeout, 24-hr brute-force lockouts. | Regression suite testing 2FA code verification & rate limiting. | Weak user-chosen passwords. | Integrate HaveIBeenPwned API for breach checking. |
| **A08: Software & Data Integrity Failures** | `APPLICABLE` | GitHub Actions CI/CD pipeline (`.github/workflows/security.yml`), encrypted database backup script (`scripts/backup_database.php`), SRI attributes on CDNs. | SAST CI workflow validation. | Unsigned git commits. | Enable signed commits (`gpg`) in repository settings. |
| **A09: Security Logging & Monitoring Failures** | `APPLICABLE` | Structured JSON audit logging (`security_logs` table + `security.log` file), CSP violation reporting (`api/csp_report.php`), automatic credential/secret redaction. | Verification of audit log insertion on logins, MFA events & lockouts. | Log storage storage limits. | Configure syslog or SIEM log forwarding (Datadog/Elastic). |
| **A10: Server-Side Request Forgery (SSRF)** | `NOT APPLICABLE` | Application does not accept user-supplied URLs or perform server-side HTTP fetching. OAuth redirect URIs are strictly validated against origin domain. | SAST scanner file parsing. | None. | Re-evaluate if URL fetching features are added in the future. |

---

## Security Verification Summary

All 9 applicable OWASP categories (**A01–A09**) have been fully implemented and verified with automated test tools (`sast_scan.php`, `dast_scan.php`, `synthetic_health_check.php`, `security_regression_test.php`). Category **A10 (SSRF)** is documented as `NOT APPLICABLE`.
