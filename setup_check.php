<?php
/**
 * ============================================================================
 *  setup_check.php — SYSTEM DIAGNOSTICS & ONE-CLICK DATABASE SETUP
 * ============================================================================
 *  Run this page in your browser (e.g. http://localhost/setup_check.php)
 *  to check your setup, create the database & table, and seed a test account.
 * ============================================================================
 */

// Load DB config constants
require_once __DIR__ . '/config/database.php';

// Start a session so the one-click setup action can be CSRF-protected.
require_once __DIR__ . '/config/session.php';

// Simple session-based CSRF token for the setup form.
function setup_csrf_token(): string
{
    if (empty($_SESSION['setup_csrf'])) {
        $_SESSION['setup_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['setup_csrf'];
}

$stepResults = [];
$dbConnected = false;
$tableExists = false;
$userSeeded  = false;
$errorMessage = '';

// 1. PHP Version Check
$phpVersion = PHP_VERSION;
$phpOk = version_compare($phpVersion, '8.0.0', '>=');

// 2. Database Connection Check (Without selecting DB first to allow auto-creation)
$connNoDb = null;
try {
    $connNoDb = @new mysqli(DB_HOST, DB_USER, DB_PASS);
    if (!$connNoDb->connect_error) {
        $dbConnected = true;
    }
} catch (Throwable $e) {
    $errorMessage = $e->getMessage();
}

// Handle Auto-Setup Action
if (isset($_POST['action']) && $_POST['action'] === 'setup_db' && $dbConnected) {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if ($submittedToken === '' || empty($_SESSION['setup_csrf']) || !hash_equals($_SESSION['setup_csrf'], $submittedToken)) {
        $errorMessage = 'Invalid security token. Please refresh the page and try again.';
    } else {
        try {
        // Create Database if not exists
        $connNoDb->query("CREATE DATABASE IF NOT EXISTS `" . DB_NAME . "` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $connNoDb->select_db(DB_NAME);

        // Create Users Table
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
            UNIQUE KEY `uq_users_email` (`email`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
        $connNoDb->query($tableSql);

        // Create password_resets table (same schema as config/database.php)
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
        $connNoDb->query($resetTableSql);

        // Create security_logs audit table
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
        $connNoDb->query($logsTableSql);

        // Check if demo user exists
        $checkUser = $connNoDb->query("SELECT id FROM users WHERE email = 'demo@gmail.com'");
        if ($checkUser->num_rows === 0) {
            $demoHash = password_hash('TestPassword@123', defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
            $stmt = $connNoDb->prepare("INSERT INTO users (fullname, email, password, role, email_verified) VALUES (?, ?, ?, ?, 1)");
            $name = 'Demo User';
            $email = 'demo@gmail.com';
            $role = 'user';
            $stmt->bind_param('ssss', $name, $email, $demoHash, $role);
            $stmt->execute();
            $stmt->close();
        }

        header('Location: setup_check.php?success=1');
        exit;
        } catch (Throwable $ex) {
            $errorMessage = $ex->getMessage();
        }
    }
}

// Re-check after potential DB creation
if ($dbConnected) {
    $dbSelected = @$connNoDb->select_db(DB_NAME);
    if ($dbSelected) {
        $res = @$connNoDb->query("SHOW TABLES LIKE 'users'");
        if ($res && $res->num_rows > 0) {
            $tableExists = true;
            $userCheck = @$connNoDb->query("SELECT COUNT(*) as cnt FROM users");
            if ($userCheck) {
                $row = $userCheck->fetch_assoc();
                $userSeeded = ($row['cnt'] > 0);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup & Diagnostic Tool — Secure Login System</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <style>
        .diag-card { max-width: 680px; margin: 2rem auto; }
        .diag-item { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1rem; border-bottom: 1px solid var(--border); }
        .badge-pass { background: #dcfce7; color: #15803d; padding: 0.25rem 0.65rem; border-radius: 99px; font-weight: 700; font-size: 0.85rem; }
        .badge-fail { background: #fee2e2; color: #b91c1c; padding: 0.25rem 0.65rem; border-radius: 99px; font-weight: 700; font-size: 0.85rem; }
        .code-box { background: #1e293b; color: #f8fafc; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.9rem; overflow-x: auto; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="card diag-card">
            <h2>&#128736; Project Setup & Diagnostics</h2>
            <p class="card-sub">Automated readiness check for local or InfinityFree hosting.</p>

            <?php if (isset($_GET['success'])): ?>
                <div class="alert alert-success">&#10004; Database created &amp; demo user seeded successfully!</div>
            <?php endif; ?>

            <?php if ($errorMessage !== ''): ?>
                <div class="alert alert-error">&#9888; Error: <?php echo htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>

            <div class="diag-item">
                <div>
                    <strong>PHP Version 8+</strong><br>
                    <small>Current version: <?php echo $phpVersion; ?></small>
                </div>
                <span class="<?php echo $phpOk ? 'badge-pass' : 'badge-fail'; ?>">
                    <?php echo $phpOk ? 'PASS' : 'WARNING (PHP 8 recommended)'; ?>
                </span>
            </div>

            <div class="diag-item">
                <div>
                    <strong>MySQL Server Connection</strong><br>
                    <small>Host: <code><?php echo DB_HOST; ?></code> | User: <code><?php echo DB_USER; ?></code></small>
                </div>
                <span class="<?php echo $dbConnected ? 'badge-pass' : 'badge-fail'; ?>">
                    <?php echo $dbConnected ? 'CONNECTED' : 'FAILED'; ?>
                </span>
            </div>

            <div class="diag-item">
                <div>
                    <strong>Database (<code><?php echo DB_NAME; ?></code>) &amp; <code>users</code> Table</strong><br>
                    <small>Required table for login credentials</small>
                </div>
                <span class="<?php echo $tableExists ? 'badge-pass' : 'badge-fail'; ?>">
                    <?php echo $tableExists ? 'READY' : 'NOT FOUND'; ?>
                </span>
            </div>

            <div class="diag-item">
                <div>
                    <strong>Demo User Seeded</strong><br>
                    <small>Login: <code>demo@gmail.com</code> / Pass: <code>TestPassword@123</code></small>
                </div>
                <span class="<?php echo $userSeeded ? 'badge-pass' : 'badge-fail'; ?>">
                    <?php echo $userSeeded ? 'READY' : 'EMPTY'; ?>
                </span>
            </div>

            <br>

            <?php if ($dbConnected && (!$tableExists || !$userSeeded)): ?>
                <form method="post" action="setup_check.php">
                    <input type="hidden" name="action" value="setup_db">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(setup_csrf_token(), ENT_QUOTES, 'UTF-8'); ?>">
                    <button type="submit" class="btn btn-primary">&#9881; Auto-Create Database &amp; Seed Demo User</button>
                </form>
            <?php elseif ($tableExists && $userSeeded): ?>
                <div class="alert alert-success">
                    &#127881; System is 100% ready! You can now test logging in.
                </div>
                <a href="login.php" class="btn btn-primary" style="display: block; text-align: center;">Go to Login Page &rarr;</a>
            <?php else: ?>
                <p style="color: var(--danger); font-size: 0.9rem;">
                    &#9888; MySQL server is not connected. Please make sure MySQL (XAMPP / WAMP) is running or check credentials in <code>config/database.php</code>.
                </p>
            <?php endif; ?>

            <br>
            <h3>Demo Login Credentials</h3>
            <div class="code-box">
Email:    demo@gmail.com
Password: TestPassword@123
            </div>

            <br>
            <p class="form-footer">
                <a href="index.php">&larr; Back to Home Page</a>
            </p>
        </div>
    </div>
</body>
</html>
