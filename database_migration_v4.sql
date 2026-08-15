-- ==============================================================================
-- DATABASE MIGRATION SCRIPT — ADVANCED PRODUCTION SECURITY (v4)
-- ==============================================================================

-- 1. Ensure `users` table contains all required columns
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `mfa_enabled` TINYINT(1) NOT NULL DEFAULT 0 AFTER `email_verified`,
    ADD COLUMN IF NOT EXISTS `mfa_secret_encrypted` TEXT DEFAULT NULL AFTER `mfa_enabled`,
    ADD COLUMN IF NOT EXISTS `mfa_recovery_codes_hash` TEXT DEFAULT NULL AFTER `mfa_secret_encrypted`,
    ADD COLUMN IF NOT EXISTS `last_password_verified_at` DATETIME DEFAULT NULL AFTER `is_active`,
    ADD COLUMN IF NOT EXISTS `risk_score` INT NOT NULL DEFAULT 0 AFTER `last_password_verified_at`;

-- 2. Ensure `user_credentials` table exists for WebAuthn / Passkeys
CREATE TABLE IF NOT EXISTS `user_credentials` (
    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED NOT NULL,
    `credential_id` VARCHAR(255) NOT NULL,
    `public_key`    TEXT NOT NULL,
    `sign_count`    INT UNSIGNED NOT NULL DEFAULT 0,
    `transports`    VARCHAR(255) DEFAULT NULL,
    `name`          VARCHAR(100) NOT NULL DEFAULT 'Default Passkey',
    `last_used_at`  DATETIME DEFAULT NULL,
    `created_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_credential_id` (`credential_id`),
    KEY `idx_cred_user_id` (`user_id`),
    CONSTRAINT `fk_cred_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Ensure `risk_events` table exists for Continuous Access Evaluation
CREATE TABLE IF NOT EXISTS `risk_events` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED DEFAULT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `risk_score` INT NOT NULL DEFAULT 0,
    `risk_level` VARCHAR(20) NOT NULL DEFAULT 'LOW',
    `details`    TEXT DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_risk_user` (`user_id`),
    KEY `idx_risk_level` (`risk_level`),
    KEY `idx_risk_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Ensure `privacy_requests` table exists for GDPR Data Access & Deletion
CREATE TABLE IF NOT EXISTS `privacy_requests` (
    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`      INT UNSIGNED NOT NULL,
    `request_type` VARCHAR(50) NOT NULL, -- 'EXPRESS_DATA' or 'DELETE_ACCOUNT'
    `status`       VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'COMPLETED', 'REJECTED'
    `requested_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `completed_at` DATETIME DEFAULT NULL,
    `details`      TEXT DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_priv_user` (`user_id`),
    KEY `idx_priv_status` (`status`),
    CONSTRAINT `fk_priv_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Ensure `csp_reports` table exists for Content Security Policy violations
CREATE TABLE IF NOT EXISTS `csp_reports` (
    `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `document_uri`       VARCHAR(255) DEFAULT NULL,
    `blocked_uri`        VARCHAR(255) DEFAULT NULL,
    `violated_directive` VARCHAR(100) DEFAULT NULL,
    `original_policy`    TEXT DEFAULT NULL,
    `ip_address`         VARCHAR(45) NOT NULL,
    `user_agent`         TEXT DEFAULT NULL,
    `created_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_csp_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
