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
if (!defined('DB_HOST')) define('DB_HOST', getenv('DB_HOST') ?: 'localhost');   // Hostname of the MySQL server
if (!defined('DB_USER')) define('DB_USER', getenv('DB_USER') ?: 'root');        // Database username
if (!defined('DB_PASS')) define('DB_PASS', getenv('DB_PASS') ?: '');            // Database password
if (!defined('DB_NAME')) define('DB_NAME', getenv('DB_NAME') ?: 'secure_login');// Database name
// -----------------------------------------------------------------------------

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

try {
    // 1. First attempt to connect directly to the target database
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    } catch (mysqli_sql_exception $e) {
        // If error is unknown database, attempt auto-creation
        $connNoDb = new mysqli(DB_HOST, DB_USER, DB_PASS);
        $connNoDb->query("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $connNoDb->close();

        // Retry connection to newly created database
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
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
        `created_at`               TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uq_users_email` (`email`),
        KEY `idx_users_google_id` (`google_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
    $conn->query($tableSql);

    // Auto-migrate: add missing columns in older schemas
    $columnsToEnsure = [
        'phone'                    => "VARCHAR(20) DEFAULT NULL AFTER `email`",
        'google_id'                => "VARCHAR(255) DEFAULT NULL AFTER `role`",
        'email_verified'           => "TINYINT(1) NOT NULL DEFAULT 0 AFTER `google_id`",
        'verification_otp_hash'    => "VARCHAR(255) DEFAULT NULL AFTER `email_verified`",
        'verification_otp_expires' => "DATETIME DEFAULT NULL AFTER `verification_otp_hash`",
        'reset_otp_hash'           => "VARCHAR(255) DEFAULT NULL AFTER `verification_otp_expires`",
        'reset_otp_expires'        => "DATETIME DEFAULT NULL AFTER `reset_otp_hash`",
        'otp_attempts'             => "INT NOT NULL DEFAULT 0 AFTER `reset_otp_expires`",
        'otp_last_sent'            => "DATETIME DEFAULT NULL AFTER `otp_attempts`",
        'failed_login_attempts'    => "INT NOT NULL DEFAULT 0 AFTER `otp_last_sent`",
        'lockout_until'            => "DATETIME DEFAULT NULL AFTER `failed_login_attempts`",
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

    // 4. Ensure demo user exists (Name: Demo User, Email demo@gmail.com, Phone +91, verified)
    $checkUser = $conn->query("SELECT id FROM users WHERE email = 'demo@gmail.com'");
    if ($checkUser && $checkUser->num_rows === 0) {
        $demoHash = password_hash('TestPassword@123', PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (fullname, email, phone, password, role, email_verified) VALUES (?, ?, ?, ?, ?, 1)");
        $name  = 'Demo User';
        $email = 'demo@gmail.com';
        $phone = '+919876543210';
        $role  = 'user';
        $stmt->bind_param('sssss', $name, $email, $phone, $demoHash, $role);
        $stmt->execute();
        $stmt->close();
    }

}
catch (mysqli_sql_exception $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    die('
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 3rem auto; padding: 2rem; border: 1px solid #fecaca; background: #fef2f2; border-radius: 12px; color: #991b1b;">
            <h2 style="margin-top:0;">&#9888; MySQL Database Connection Required</h2>
            <p>Unable to connect to the MySQL database server (<code>' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</code>).</p>
            <hr style="border:0; border-top:1px solid #fca5a5; margin:1rem 0;">
            <p><strong>How to fix this:</strong></p>
            <ol>
                <li>Open the <strong>XAMPP Control Panel</strong> and make sure <strong>MySQL</strong> is started (green indicator).</li>
                <li>Or verify database credentials in <code>config/database.php</code>.</li>
            </ol>
            <p><a href="setup_check.php" style="color: #4f46e5; font-weight: bold;">Run System Setup Check &rarr;</a></p>
        </div>
    ');
}
