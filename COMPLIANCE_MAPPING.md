# Security Compliance Control Mapping (PCI DSS, HIPAA, ISO 27001)

> [!IMPORTANT]
> **CONTROL MAPPING ONLY — NOT A COMPLIANCE CERTIFICATION**
> This document maps implemented application security controls against industry standards (PCI DSS v4.0, HIPAA Security Rule, ISO/IEC 27001:2022). Formal compliance certification requires organizational, physical, hosting, and legal audits beyond software source code.

---

## 1. PCI DSS v4.0 Control Mapping

| PCI DSS v4.0 Requirement | Implemented Security Control | Status |
|---|---|---|
| **Req 8.2.1**: Strong User Authentication | `password_hash()` (Argon2id/bcrypt), 6-digit OTP verification, WebAuthn Passkeys support | `IMPLEMENTED` |
| **Req 8.3.1**: Multi-Factor Authentication (MFA) | RFC 6238 TOTP Authenticator 2FA (`mfa_enroll.php`, `mfa_verify.php`), mandatory for Admins | `IMPLEMENTED` |
| **Req 8.3.6**: Password Complexity & Length | Password validation requiring min 8-12 chars, uppercase, lowercase, numbers, special characters | `IMPLEMENTED` |
| **Req 8.3.4**: Session Protection & Fixation | `session_regenerate_id(true)` upon login, strict mode, HttpOnly/Secure/SameSite=Lax cookies | `IMPLEMENTED` |
| **Req 8.3.7**: Rate Limiting & Account Lockout | Persistent database-backed rate limiting (`check_rate_limit()`), 24-hour progressive lockout | `IMPLEMENTED` |
| **Req 10.2.1**: Audit Logging of Auth Events | Structured JSON audit logging (`log_security_event()`, `security_logs` table) for logins, lockouts, role changes | `IMPLEMENTED` |
| **Req 3.4.1**: Encryption of Sensitive Data | AES-256-GCM authenticated encryption at rest (`encrypt_pii()`) for non-password sensitive user fields | `IMPLEMENTED` |

---

## 2. HIPAA Security Rule (45 CFR § 164.312)

| HIPAA Technical Safeguard | Implemented Security Control | Status |
|---|---|---|
| **§ 164.312(a)(1)**: Access Control & Unique User ID | Unique user ID, server-side RBAC (`require_admin()`), IDOR ownership checks (`can_access_user_resource()`) | `IMPLEMENTED` |
| **§ 164.312(a)(2)(iii)**: Automatic Logoff | Sliding 30-minute server-side session inactivity timeout in `config/session.php` | `IMPLEMENTED` |
| **§ 164.312(b)**: Audit Controls | Append-only `security.log` file + MySQL `security_logs` audit table logging all security events | `IMPLEMENTED` |
| **§ 164.312(c)(1)**: Data Integrity | Prepared statements preventing SQL injection, timing-safe CSRF token checks (`hash_equals()`) | `IMPLEMENTED` |
| **§ 164.312(e)(1)**: Transmission Security | Mandatory HSTS (`Strict-Transport-Security`), site-wide HTTPS 301 redirection in `.htaccess` and `session.php` | `IMPLEMENTED` |

---

## 3. ISO/IEC 27001:2022 Control Mapping

| ISO 27001:2022 Control | Implemented Security Control | Status |
|---|---|---|
| **A.5.15**: Access Control | Server-side role-based access control, least-privilege admin panel, direct URL protection | `IMPLEMENTED` |
| **A.8.24**: Use of Cryptography | Argon2id/bcrypt password hashing, AES-256-GCM PII encryption, TLS 1.3/HTTPS transport | `IMPLEMENTED` |
| **A.8.7**: Protection Against Malware | Strict Content Security Policy (`script-src 'self'`), 0 inline scripts, input escaping (`e()`) | `IMPLEMENTED` |
| **A.8.12**: Data Leakage Prevention | Sensitive field redaction in log files, `.htaccess` blocking direct access to `.env`, `.sql`, `.log`, `backups/` | `IMPLEMENTED` |
| **A.8.14**: Redundancy & Backups | Encrypted database backup script (`scripts/backup_database.php`) with AES-256-GCM payload encryption | `IMPLEMENTED` |

---

## 4. Missing Infrastructure & Organizational Controls
To achieve full formal compliance, the hosting infrastructure must provide:
1. **Web Application Firewall (WAF)**: Cloudflare WAF / AWS WAF for edge inspection.
2. **DDoS Protection & CDN**: Cloudflare DDoS protection for origin shield.
3. **Physical & Cloud Hosting Compliance**: Hosting provider (AWS, GCP, Azure) certified SOC2 / ISO 27001.
4. **Third-Party Security Audit & Penetration Testing**: External annual pen test report.
