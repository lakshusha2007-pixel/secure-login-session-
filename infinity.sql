-- ==============================================================================
-- INFINITYFREE COMPLETE PRODUCTION DATABASE SCHEMA (infinity.sql)
-- ==============================================================================
-- Target Database: if0_42659488_database
-- Compatibility: MySQL 5.7+ / MySQL 8.0+ / MariaDB 10.x
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------------------------
-- 1. USERS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id`                       INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `fullname`                 VARCHAR(100) NOT NULL,
    `email`                    VARCHAR(255) NOT NULL,
    `phone`                    VARCHAR(20)  DEFAULT NULL,
    `phone_encrypted`          TEXT         DEFAULT NULL,
    `avatar`                   VARCHAR(255) DEFAULT NULL,
    `password`                 VARCHAR(255) NOT NULL,
    `role`                     VARCHAR(50)  NOT NULL DEFAULT 'user',
    `google_id`                VARCHAR(255) DEFAULT NULL,
    `email_verified`           TINYINT(1)   NOT NULL DEFAULT 0,
    `mfa_enabled`              TINYINT(1)   NOT NULL DEFAULT 0,
    `mfa_secret_encrypted`     TEXT         DEFAULT NULL,
    `mfa_recovery_codes_hash`  TEXT         DEFAULT NULL,
    `verification_otp_hash`    VARCHAR(255) DEFAULT NULL,
    `verification_otp_expires` DATETIME     DEFAULT NULL,
    `reset_otp_hash`           VARCHAR(255) DEFAULT NULL,
    `reset_otp_expires`        DATETIME     DEFAULT NULL,
    `otp_attempts`             INT          NOT NULL DEFAULT 0,
    `otp_last_sent`            DATETIME     DEFAULT NULL,
    `failed_login_attempts`    INT          NOT NULL DEFAULT 0,
    `lockout_until`            DATETIME     DEFAULT NULL,
    `is_active`                TINYINT(1)   NOT NULL DEFAULT 1,
    `last_password_verified_at` DATETIME    DEFAULT NULL,
    `risk_score`               INT          NOT NULL DEFAULT 0,
    `verification_token`       VARCHAR(255) DEFAULT NULL,
    `verification_expires`     DATETIME     DEFAULT NULL,
    `created_at`               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_users_email` (`email`),
    KEY `idx_users_role` (`role`),
    KEY `idx_users_google_id` (`google_id`),
    KEY `idx_users_lockout` (`lockout_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 2. PASSWORD RESETS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED NOT NULL,
    `token_hash` VARCHAR(255) NOT NULL,
    `expires_at` DATETIME     NOT NULL,
    `used_at`    DATETIME     DEFAULT NULL,
    `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_resets_user_id` (`user_id`),
    KEY `idx_resets_token_hash` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 3. SECURITY AUDIT LOGS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `security_logs` (
    `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED DEFAULT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `ip_address` VARCHAR(45)  NOT NULL,
    `user_agent` TEXT         DEFAULT NULL,
    `details`    TEXT         DEFAULT NULL,
    `severity`   ENUM('INFO', 'WARNING', 'ALERT', 'CRITICAL') NOT NULL DEFAULT 'INFO',
    `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_logs_user_id` (`user_id`),
    KEY `idx_logs_event_type` (`event_type`),
    KEY `idx_logs_severity` (`severity`),
    KEY `idx_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 4. RATE LIMITS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `rate_key`      VARCHAR(255) NOT NULL,
    `action`        VARCHAR(100) NOT NULL,
    `attempts`      INT          NOT NULL DEFAULT 1,
    `last_attempt`  DATETIME     NOT NULL,
    `lockout_until` DATETIME     DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_rate_key_action` (`rate_key`, `action`),
    KEY `idx_rate_lockout` (`lockout_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 5. USER SESSIONS TABLE (Active Session Tracking & Remote Revocation)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_sessions` (
    `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`            INT UNSIGNED NOT NULL,
    `session_token_hash` VARCHAR(64)  NOT NULL,
    `ip_address`         VARCHAR(45)  NOT NULL,
    `user_agent`         TEXT         DEFAULT NULL,
    `last_activity`      DATETIME     NOT NULL,
    `created_at`         DATETIME     NOT NULL,
    `is_revoked`         TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_session_hash` (`session_token_hash`),
    KEY `idx_sessions_user_id` (`user_id`),
    KEY `idx_sessions_revoked` (`is_revoked`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 6. SCOPED API KEYS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `api_keys` (
    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`      INT UNSIGNED NOT NULL,
    `key_name`     VARCHAR(100) NOT NULL,
    `key_prefix`   VARCHAR(16)  NOT NULL,
    `key_hash`     VARCHAR(64)  NOT NULL,
    `scopes`       VARCHAR(255) NOT NULL DEFAULT 'read:profile',
    `expires_at`   DATETIME     DEFAULT NULL,
    `is_revoked`   TINYINT(1)   NOT NULL DEFAULT 0,
    `last_used_at` DATETIME     DEFAULT NULL,
    `created_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_api_key_hash` (`key_hash`),
    KEY `idx_api_keys_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 7. RISK MONITORING & CONTINUOUS ACCESS EVALUATION
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `risk_events` (
    `id`          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`     INT UNSIGNED DEFAULT NULL,
    `ip_address`  VARCHAR(45)  NOT NULL,
    `event_type`  VARCHAR(100) NOT NULL,
    `risk_level`  ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'LOW',
    `risk_score`  INT          NOT NULL DEFAULT 0,
    `metadata`    TEXT         DEFAULT NULL,
    `created_at`  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_risk_user_id` (`user_id`),
    KEY `idx_risk_level` (`risk_level`),
    KEY `idx_risk_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 8. PRIVACY & GDPR DSAR REQUESTS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `privacy_requests` (
    `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`      INT UNSIGNED NOT NULL,
    `request_type` ENUM('EXPORT', 'DELETE', 'RECTIFY') NOT NULL,
    `status`       ENUM('PENDING', 'PROCESSING', 'COMPLETED', 'REJECTED') NOT NULL DEFAULT 'PENDING',
    `notes`        TEXT         DEFAULT NULL,
    `created_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `resolved_at`  DATETIME     DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_privacy_user_id` (`user_id`),
    KEY `idx_privacy_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 9. CONTENT SECURITY POLICY (CSP) VIOLATION REPORTS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `csp_reports` (
    `id`                 INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `document_uri`       VARCHAR(255) DEFAULT NULL,
    `referrer`           VARCHAR(255) DEFAULT NULL,
    `blocked_uri`        VARCHAR(255) DEFAULT NULL,
    `violated_directive` VARCHAR(255) DEFAULT NULL,
    `original_policy`    TEXT         DEFAULT NULL,
    `disposition`        VARCHAR(50)  DEFAULT 'enforce',
    `raw_report`         TEXT         DEFAULT NULL,
    `ip_address`         VARCHAR(45)  DEFAULT NULL,
    `created_at`         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_csp_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 10. WEBAUTHN / PASSKEYS CREDENTIALS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_credentials` (
    `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`          INT UNSIGNED NOT NULL,
    `credential_id`    VARCHAR(255) NOT NULL,
    `public_key`       TEXT         NOT NULL,
    `sign_count`       BIGINT       NOT NULL DEFAULT 0,
    `transports`       VARCHAR(255) DEFAULT '["internal"]',
    `attestation_type` VARCHAR(100) DEFAULT 'none',
    `created_at`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_credential_id` (`credential_id`),
    KEY `idx_cred_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- SEED DEFAULT USERS (Passwords hashed using standard bcrypt/password_hash)
-- Demo User:    demo@gmail.com    / Password: TestPassword@123
-- System Admin: admin@gmail.com   / Password: AdminPassword@123
-- ------------------------------------------------------------------------------
INSERT INTO `users` (`fullname`, `email`, `password`, `role`, `email_verified`, `is_active`)
VALUES 
('Demo User', 'demo@gmail.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'user', 1, 1),
('System Admin', 'admin@gmail.com', '$2y$10$eWJq2u4xMhRjS2yN6Uq7.OCiVzLq4E2/7a2q4k3p5x1v8m9n0b2c1', 'admin', 1, 1)
ON DUPLICATE KEY UPDATE `email_verified` = 1, `is_active` = 1;

SET FOREIGN_KEY_CHECKS = 1;
