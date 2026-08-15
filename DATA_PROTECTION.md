# PII Minimization & Data Protection Specification

This document details the personal data minimization review, encryption standards at rest, and field-level encryption architecture enforced within the SecureAuth application.

---

## 1. PII Minimization Review

For every collected attribute, the application enforces strict minimization principles ("Collect only what is strictly required"):

| Attribute Name | Stored Location | Necessity Justification | Encryption / Protection Standard |
|---|---|---|---|
| **Full Name** | `users.fullname` | Display identification in UI and emails | Escaped on output (`e()`), optional input validation |
| **Email Address** | `users.email` | Primary authentication identifier & notifications | Unique index, normalized, validated against Gmail rules |
| **Password** | `users.password` | Credential verification | **Argon2id** (`memory_cost=64MB, time_cost=4`) / **bcrypt** (cost 12). Reversible encryption is strictly forbidden. |
| **Phone Number** | `users.phone_encrypted` | Recoverable contact info for MFA/SMS | **Authenticated AES-256-GCM field-level encryption** at rest using `APP_ENCRYPTION_KEY`. |
| **MFA TOTP Secret** | `users.mfa_secret_encrypted` | Authenticator TOTP verification | **AES-256-GCM field-level encryption** at rest. |
| **API Key Secrets** | `api_keys.key_hash` | API Authentication | **SHA-256 hash** only. Raw key is never stored. |

---

## 2. Encryption Key Management & Rotation

1. **Key Derivation & Storage**:
   - Master encryption key is stored in `.env` under `APP_ENCRYPTION_KEY` (outside public web root).
   - Encryption key is never hardcoded in PHP source files or stored in database tables.

2. **Field-Level Encryption Architecture**:
   - `encrypt_pii(string $plaintext)`: Generates 16-byte random IV, encrypts via AES-256-GCM, produces 16-byte authentication tag, and returns Base64 string.
   - `decrypt_pii(string $ciphertext)`: Verifies GCM authentication tag before returning plaintext. Returns original input if tag fails (detects tampering).

3. **Key Rotation Support**:
   - `rotate_field_encryption_key($conn, $oldKey, $newKey)` utility function re-encrypts all database PII fields transparently when rotating encryption keys.
