# Data Retention & Automated Cleanup Policy

This document defines the storage lifetime, retention justification, deletion procedures, and automated cleanup schedules for all data assets stored within the SecureAuth system.

---

## 1. Data Asset Retention Matrix

| Data Classification | Storage Entity | Purpose | Retention Period | Deletion Trigger / Cleanup Action |
|---|---|---|---|---|
| **User Account Credentials** | `users` table | User authentication & authorization | Lifetime of account | Hard deleted upon user GDPR request or admin account deletion |
| **Email Verification OTPs** | `users.verification_otp_hash` | Email address verification | 60 seconds | Automatically nulled upon expiration or verification |
| **Password Reset OTPs** | `users.reset_otp_hash` / `password_resets` | Account password recovery | 60 seconds / 1 hour | Automatically deleted upon use or expiration via `scripts/cleanup.php` |
| **Rate Limit Lockouts** | `rate_limits` table | Persistent brute-force protection | Duration of lockout (15 mins - 24 hours) | Automatically reset upon window expiration |
| **Security Audit Logs** | `security_logs` table | System audit & threat detection | 90 days | Automatically purged via daily cron (`scripts/cleanup.php`) |
| **Impersonation Logs** | `impersonation_logs` table | Administrative audit compliance | 365 days | Archived / Purged after 1 year |
| **Session State Data** | Server PHP Sessions | User state management | 30 minutes inactivity | Server-side session destroy upon timeout or logout |

---

## 2. Automated Cleanup Schedule

Automated cleanup is executed by running `scripts/cleanup.php` via CLI cron or system task scheduler.

### Recommended Cron Setup:
```bash
# Execute data retention cleanup daily at midnight
0 0 * * * /usr/bin/php /home/vol15_1/epizy.com/epiz_12345678/htdocs/scripts/cleanup.php >/dev/null 2>&1
```

### Cleanup Functionality:
- Purges expired password reset tokens (`expires_at < NOW()`).
- Clears expired OTP verification hashes.
- Removes expired rate-limit records (`lockout_until < NOW()`).
- Purges security logs older than 90 days (`created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)`).

---

## 3. Account & Data Deletion Procedures

1. **User-Initiated Deletion**:
   - Users can trigger immediate account deletion via `/api/v1/delete_account.php`.
   - Associated API keys (`api_keys`), MFA credentials (`user_credentials`), and active sessions are cascade deleted.

2. **Admin-Initiated Deletion**:
   - Super Administrators can deactivate or remove accounts via `/admin/users.php`.
