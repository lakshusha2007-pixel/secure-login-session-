-- ==============================================================================
-- DATABASE MIGRATION SCRIPT — SECURE LOGIN & SESSION SYSTEM (2.1-2.5)
-- ==============================================================================

-- 1. Ensure `users` table columns exist
ALTER TABLE `users`
    ADD COLUMN IF NOT EXISTS `phone_encrypted` TEXT DEFAULT NULL AFTER `phone`,
    ADD COLUMN IF NOT EXISTS `role` VARCHAR(50) NOT NULL DEFAULT 'user' AFTER `password`,
    ADD COLUMN IF NOT EXISTS `is_active` TINYINT(1) NOT NULL DEFAULT 1 AFTER `lockout_until`;

-- 2. Create `rate_limits` table for server-side rate limiting
CREATE TABLE IF NOT EXISTS `rate_limits` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `rate_key` VARCHAR(255) NOT NULL,
    `action` VARCHAR(100) NOT NULL,
    `attempts` INT NOT NULL DEFAULT 1,
    `last_attempt` DATETIME NOT NULL,
    `lockout_until` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_rate_key_action` (`rate_key`, `action`),
    KEY `idx_rate_lockout` (`lockout_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Ensure `password_resets` table exists
CREATE TABLE IF NOT EXISTS `password_resets` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `token_hash` VARCHAR(255) NOT NULL,
    `expires_at` DATETIME NOT NULL,
    `used_at` DATETIME DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_resets_user_id` (`user_id`),
    KEY `idx_resets_token_hash` (`token_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Ensure `security_logs` table exists
CREATE TABLE IF NOT EXISTS `security_logs` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED DEFAULT NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `user_agent` TEXT DEFAULT NULL,
    `details` TEXT DEFAULT NULL,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'INFO',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_logs_event` (`event_type`),
    KEY `idx_logs_user` (`user_id`),
    KEY `idx_logs_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Seed default admin user (email: admin@gmail.com, password: AdminPassword@123, role: admin)
INSERT INTO `users` (`fullname`, `email`, `phone`, `password`, `role`, `email_verified`, `is_active`)
SELECT 'System Admin', 'admin@gmail.com', '+919876543211', '$2y$12$R.vL0a1c.Z5eYpW2qXg4/.dJ4wY1c8z5g5G4a2B1C3D5E7F9G0H1I', 'admin', 1, 1
WHERE NOT EXISTS (SELECT `id` FROM `users` WHERE `email` = 'admin@gmail.com');
