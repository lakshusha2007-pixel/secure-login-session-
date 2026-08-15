<?php
/**
 * ============================================================================
 *  config/database.php — DATABASE CONNECTION (MySQL via MySQLi)
 * ============================================================================
 *  Creates a single reusable MySQL connection ($conn).
 *  Auto-provisions the database, table (with phone & OTP fields), and demo user.
 * ============================================================================
 */

// Load environment loader
require_once __DIR__ . '/env.php';

// --- Database connection settings ---
$resolvedHost = getenv('DB_HOST') ?: ($_ENV['DB_HOST'] ?? ($_SERVER['DB_HOST'] ?? '127.0.0.1'));
$resolvedPort = (int)(getenv('DB_PORT') ?: ($_ENV['DB_PORT'] ?? ($_SERVER['DB_PORT'] ?? 3306)));
$resolvedUser = getenv('DB_USER') ?: ($_ENV['DB_USER'] ?? ($_SERVER['DB_USER'] ?? 'root'));
$resolvedPass = getenv('DB_PASS') !== false ? getenv('DB_PASS') : ($_ENV['DB_PASS'] ?? ($_SERVER['DB_PASS'] ?? ''));
$resolvedName = getenv('DB_NAME') ?: ($_ENV['DB_NAME'] ?? ($_SERVER['DB_NAME'] ?? 'secure_login'));

if (!defined('DB_HOST')) define('DB_HOST', $resolvedHost);
if (!defined('DB_PORT')) define('DB_PORT', $resolvedPort);
if (!defined('DB_USER')) define('DB_USER', $resolvedUser);
if (!defined('DB_PASS')) define('DB_PASS', $resolvedPass);
if (!defined('DB_NAME')) define('DB_NAME', $resolvedName);
// -----------------------------------------------------------------------------

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    // 1. First attempt to connect directly to the target database
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
    } catch (mysqli_sql_exception $e) {
        // If error is unknown database on local server, attempt auto-creation
        try {
            $connNoDb = new mysqli(DB_HOST, DB_USER, DB_PASS, null, DB_PORT);
            $connNoDb->query("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $connNoDb->close();

            // Retry connection to newly created database
            $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
        } catch (Throwable $innerEx) {
            // Re-throw original database connection exception
            throw $e;
        }
    }

    $conn->set_charset('utf8mb4');

    // 2. Ensure users table exists with google_id, email verification, and OTP fields
    $tableSql = "CREATE TABLE IF NOT EXISTS `users` (
        `id`                       INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `fullname`                 VARCHAR(100) NOT NULL,
        `email`                    VARCHAR(255) NOT NULL,
        `phone`                    VARCHAR(20)  DEFAULT NULL,
        `password`                 VARCHAR(255) NOT NULL,
        `role`                     VARCHAR(50)  NOT NULL DEFAULT 'user',
        `google_id`                VARCHAR(255) DEFAULT NULL,
        `email_verified`           TINYINT(1)   NOT NULL DEFAULT 0,
        `verification_otp_hash`    VARCHAR(255) DEFAULT NULL,
        `verification_otp_expires` DATETIME     DEFAULT NULL,
        `reset_otp_hash`           VARCHAR(255) DEFAULT NULL,
        `reset_otp_expires`        DATETIME     DEFAULT NULL,
        `otp_attempts`             INT          NOT NULL DEFAULT 0,
        `otp_last_sent`            DATETIME     DEFAULT NULL,
        `failed_login_attempts`    INT          NOT NULL DEFAULT 0,
        `lockout_until`            DATETIME     DEFAULT NULL,
        `is_active`                TINYINT(1)   NOT NULL DEFAULT 1,
        `verification_token`       VARCHAR(255) DEFAULT NULL,
        `verification_expires`     DATETIME     DEFAULT NULL,
        `created_at`               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uq_users_email` (`email`),
        KEY `idx_users_google_id` (`google_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($tableSql);

    // Auto-migrate: add missing columns in older schemas
    $columnsToEnsure = [
        'phone'                    => "VARCHAR(20) DEFAULT NULL AFTER `email`",
        'phone_encrypted'          => "TEXT DEFAULT NULL AFTER `phone`",
        'avatar'                   => "VARCHAR(255) DEFAULT NULL AFTER `phone_encrypted`",
        'google_id'                => "VARCHAR(255) DEFAULT NULL AFTER `role`",

        'email_verified'           => "TINYINT(1) NOT NULL DEFAULT 0 AFTER `google_id`",
        'mfa_enabled'              => "TINYINT(1) NOT NULL DEFAULT 0 AFTER `email_verified`",
        'mfa_secret_encrypted'     => "TEXT DEFAULT NULL AFTER `mfa_enabled`",
        'mfa_recovery_codes_hash'  => "TEXT DEFAULT NULL AFTER `mfa_secret_encrypted`",
        'verification_otp_hash'    => "VARCHAR(255) DEFAULT NULL AFTER `mfa_recovery_codes_hash`",
        'verification_otp_expires' => "DATETIME DEFAULT NULL AFTER `verification_otp_hash`",
        'reset_otp_hash'           => "VARCHAR(255) DEFAULT NULL AFTER `verification_otp_expires`",
        'reset_otp_expires'        => "DATETIME DEFAULT NULL AFTER `reset_otp_hash`",
        'otp_attempts'             => "INT NOT NULL DEFAULT 0 AFTER `reset_otp_expires`",
        'otp_last_sent'            => "DATETIME DEFAULT NULL AFTER `otp_attempts`",
        'failed_login_attempts'    => "INT NOT NULL DEFAULT 0 AFTER `otp_last_sent`",
        'lockout_until'            => "DATETIME DEFAULT NULL AFTER `failed_login_attempts`",
        'is_active'                => "TINYINT(1) NOT NULL DEFAULT 1 AFTER `lockout_until`",
        'last_password_verified_at'=> "DATETIME DEFAULT NULL AFTER `is_active`",
        'verification_token'       => "VARCHAR(255) DEFAULT NULL AFTER `last_password_verified_at`",
        'verification_expires'     => "DATETIME DEFAULT NULL AFTER `verification_token`",
    ];

    foreach ($columnsToEnsure as $colName => $colDef) {
        try {
            $checkCol = $conn->query("SHOW COLUMNS FROM `users` LIKE '$colName'");
            if ($checkCol && $checkCol->num_rows === 0) {
                $conn->query("ALTER TABLE `users` ADD COLUMN `$colName` $colDef");
            }
        } catch (Throwable $t) {
            // Column exists or syntax variation
        }
    }

    // 3. Ensure password_resets table exists
    $resetTableSql = "CREATE TABLE IF NOT EXISTS `password_resets` (
        `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `user_id`    INT UNSIGNED NOT NULL,
        `token_hash` VARCHAR(255) NOT NULL,
        `expires_at` DATETIME     NOT NULL,
        `used_at`    DATETIME     DEFAULT NULL,
        `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        KEY `idx_resets_user_id` (`user_id`),
        KEY `idx_resets_token_hash` (`token_hash`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($resetTableSql);

    // 4. Ensure security_logs audit table exists
    $logsTableSql = "CREATE TABLE IF NOT EXISTS `security_logs` (
        `id`         INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `user_id`    INT UNSIGNED DEFAULT NULL,
        `event_type` VARCHAR(100) NOT NULL,
        `ip_address` VARCHAR(45)  NOT NULL,
        `user_agent` TEXT         DEFAULT NULL,
        `details`    TEXT         DEFAULT NULL,
        `severity`   VARCHAR(20)  NOT NULL DEFAULT 'INFO',
        `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        KEY `idx_logs_event` (`event_type`),
        KEY `idx_logs_user` (`user_id`),
        KEY `idx_logs_created` (`created_at`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($logsTableSql);

    // 5. Ensure rate_limits table exists
    $rateTableSql = "CREATE TABLE IF NOT EXISTS `rate_limits` (
        `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
        `rate_key`      VARCHAR(255) NOT NULL,
        `action`        VARCHAR(100) NOT NULL,
        `attempts`      INT NOT NULL DEFAULT 1,
        `last_attempt`  DATETIME NOT NULL,
        `lockout_until` DATETIME DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uq_rate_key_action` (`rate_key`, `action`),
        KEY `idx_rate_lockout` (`lockout_until`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($rateTableSql);

    // 6. Ensure user_credentials table exists (for WebAuthn Passkeys)
    $credTableSql = "CREATE TABLE IF NOT EXISTS `user_credentials` (
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
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($credTableSql);


    // 6. Ensure demo user exists (Name: Demo User, Email demo@gmail.com, Phone +91, verified)
    $checkUser = $conn->query("SELECT id FROM users WHERE email = 'demo@gmail.com'");
    if ($checkUser && $checkUser->num_rows === 0) {
        $demoHash = password_hash('TestPassword@123', defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (fullname, email, phone, password, role, email_verified) VALUES (?, ?, ?, ?, ?, 1)");
        $name  = 'Demo User';
        $email = 'demo@gmail.com';
        $phone = '+919876543210';
        $role  = 'user';
        $stmt->bind_param('sssss', $name, $email, $phone, $demoHash, $role);
        $stmt->execute();
        $stmt->close();
    }

    // 7. Ensure demo admin exists (Name: System Admin, Email admin@gmail.com, role: admin)
    $checkAdmin = $conn->query("SELECT id FROM users WHERE email = 'admin@gmail.com'");
    if ($checkAdmin && $checkAdmin->num_rows === 0) {
        $adminHash = password_hash('AdminPassword@123', defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (fullname, email, phone, password, role, email_verified) VALUES (?, ?, ?, ?, ?, 1)");
        $name  = 'System Admin';
        $email = 'admin@gmail.com';
        $phone = '+919876543211';
        $role  = 'admin';
        $stmt->bind_param('sssss', $name, $email, $phone, $adminHash, $role);
        $stmt->execute();
        $stmt->close();
    }

}
catch (mysqli_sql_exception $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    die('
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 3rem auto; padding: 2rem; border: 1px solid #fecaca; background: #fef2f2; border-radius: 12px; color: #991b1b;">
            <h2 style="margin-top:0;">&#9888; Database Service Unavailable</h2>
            <p>We are currently unable to connect to the authentication database. Please ensure your MySQL server is running or contact the system administrator.</p>
            <hr style="border:0; border-top:1px solid #fca5a5; margin:1rem 0;">
            <p><strong>Troubleshooting:</strong> Make sure MySQL is active in your server control panel (e.g. XAMPP / MAMP / InfinityFree).</p>
        </div>
    ');
}
