-- ==============================================================================
-- DATABASE MIGRATION SCRIPT — SECTION 2 SECURITY UPGRADE
-- ==============================================================================

-- 1. Ensure `users` table role column supports `super_admin`
ALTER TABLE `users` 
    MODIFY COLUMN `role` VARCHAR(50) NOT NULL DEFAULT 'user';

-- 2. Create `api_keys` table for scoped and rotatable API keys
CREATE TABLE IF NOT EXISTS `api_keys` (
    `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`        INT UNSIGNED NOT NULL,
    `key_identifier` VARCHAR(64) NOT NULL,
    `key_hash`       VARCHAR(255) NOT NULL,
    `name`           VARCHAR(100) NOT NULL DEFAULT 'Default API Key',
    `scopes`         TEXT NOT NULL,
    `last_used_at`   DATETIME DEFAULT NULL,
    `expires_at`     DATETIME DEFAULT NULL,
    `is_revoked`     TINYINT(1) NOT NULL DEFAULT 0,
    `created_at`     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_key_identifier` (`key_identifier`),
    KEY `idx_api_keys_user_id` (`user_id`),
    CONSTRAINT `fk_api_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Create `impersonation_logs` table for administrative audit tracking
CREATE TABLE IF NOT EXISTS `impersonation_logs` (
    `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `admin_id`       INT UNSIGNED NOT NULL,
    `target_user_id` INT UNSIGNED NOT NULL,
    `reason`         VARCHAR(255) DEFAULT NULL,
    `started_at`     DATETIME NOT NULL,
    `ended_at`       DATETIME DEFAULT NULL,
    `ip_address`     VARCHAR(45) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_imp_admin` (`admin_id`),
    KEY `idx_imp_target` (`target_user_id`),
    CONSTRAINT `fk_imp_admin` FOREIGN KEY (`admin_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_imp_target` FOREIGN KEY (`target_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Seed Super Admin user if not exists (Email: superadmin@gmail.com, Password: SuperAdminPassword@123)
INSERT INTO `users` (`fullname`, `email`, `phone`, `password`, `role`, `email_verified`, `is_active`)
SELECT 'Super Administrator', 'superadmin@gmail.com', '+919876543210', '$2y$12$R.vL0a1c.Z5eYpW2qXg4/.dJ4wY1c8z5g5G4a2B1C3D5E7F9G0H1I', 'super_admin', 1, 1
WHERE NOT EXISTS (SELECT `id` FROM `users` WHERE `email` = 'superadmin@gmail.com');
