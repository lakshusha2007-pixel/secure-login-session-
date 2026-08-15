-- ==============================================================================
-- DATABASE MIGRATION SCRIPT — ADVANCED SECURITY HARDENING (3.1-3.5)
-- ==============================================================================

-- 1. Ensure `users` table columns exist for MFA, Step-Up Auth, and Passkeys
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `mfa_enabled` TINYINT(1) NOT NULL DEFAULT 0 AFTER `email_verified`,
    ADD COLUMN IF NOT EXISTS `mfa_secret_encrypted` TEXT DEFAULT NULL AFTER `mfa_enabled`,
    ADD COLUMN IF NOT EXISTS `mfa_recovery_codes_hash` TEXT DEFAULT NULL AFTER `mfa_secret_encrypted`,
    ADD COLUMN IF NOT EXISTS `last_password_verified_at` DATETIME DEFAULT NULL AFTER `is_active`;

-- 2. Create `user_credentials` table for WebAuthn / Passkeys
CREATE TABLE IF NOT EXISTS `user_credentials` (
    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED NOT NULL,
    `credential_id` VARCHAR(255) NOT NULL,
    `public_key`    TEXT NOT NULL,
    `sign_count`    INT UNSIGNED NOT NULL DEFAULT 0,
    `transports`    VARCHAR(255) DEFAULT NULL,
    `created_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_credential_id` (`credential_id`),
    KEY `idx_cred_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
