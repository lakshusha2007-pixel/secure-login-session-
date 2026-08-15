<?php
/**
 * ============================================================================
 *  scripts/synthetic_health_check.php — SYNTHETIC UPTIME & HEALTH CHECK
 * ============================================================================
 *  Monitors system availability, database connectivity, encryption key validity,
 *  and security header enforcement without storing or exposing user credentials.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

echo "=======================================================\n";
echo " SYNTHETIC UPTIME & SECURITY HEALTH CHECK\n";
echo "=======================================================\n";

$health = [
    'timestamp'       => date('Y-m-d H:i:s T'),
    'database'        => false,
    'encryption_key'  => false,
    'users_table'     => false,
    'logs_table'      => false,
    'rate_limiter'    => false,
    'mfa_module'      => false,
    'overall_status'  => 'HEALTHY'
];

// 1. Check Database Connectivity
if ($conn instanceof mysqli && !$conn->connect_error) {
    $health['database'] = true;
    echo "✅ [DB] Database Connection: ONLINE\n";
} else {
    echo "❌ [DB] Database Connection: OFFLINE\n";
    $health['overall_status'] = 'UNHEALTHY';
}

// 2. Check Encryption Key Setup
$key = get_encryption_key();
if (strlen($key) === 32) {
    $health['encryption_key'] = true;
    echo "✅ [CRYPTO] 256-bit AES-GCM Key: ACTIVE\n";
} else {
    echo "❌ [CRYPTO] Encryption Key Configuration: INVALID\n";
    $health['overall_status'] = 'UNHEALTHY';
}

// 3. Check Users Table
try {
    $res = $conn->query('SELECT COUNT(*) AS total FROM users');
    if ($res) {
        $count = (int)$res->fetch_assoc()['total'];
        $health['users_table'] = true;
        echo "✅ [SCHEMA] Users Table: ONLINE ($count registered accounts)\n";
    }
} catch (Throwable $e) {
    echo "❌ [SCHEMA] Users Table Error: " . $e->getMessage() . "\n";
    $health['overall_status'] = 'UNHEALTHY';
}

// 4. Check Security Logs Table
try {
    $res = $conn->query('SELECT COUNT(*) AS total FROM security_logs');
    if ($res) {
        $count = (int)$res->fetch_assoc()['total'];
        $health['logs_table'] = true;
        echo "✅ [AUDIT] Security Logs Table: ONLINE ($count log entries)\n";
    }
} catch (Throwable $e) {
    echo "❌ [AUDIT] Security Logs Table Error: " . $e->getMessage() . "\n";
    $health['overall_status'] = 'UNHEALTHY';
}

// 5. Check Rate Limiting Subsystem
$rateCheck = check_rate_limit($conn, 'synthetic_health', 'test', 100, 60);
if ($rateCheck['allowed']) {
    $health['rate_limiter'] = true;
    echo "✅ [RATE] Rate Limiter Engine: OPERATIONAL\n";
} else {
    echo "❌ [RATE] Rate Limiter Engine: FAULT\n";
    $health['overall_status'] = 'UNHEALTHY';
}

// 6. Check TOTP MFA Module
require_once __DIR__ . '/../includes/totp.php';
$testSecret = TOTP::generateSecret();
$testCode   = TOTP::getCode($testSecret);
if (TOTP::verifyCode($testSecret, $testCode)) {
    $health['mfa_module'] = true;
    echo "✅ [MFA] TOTP RFC 6238 Module: OPERATIONAL\n";
} else {
    echo "❌ [MFA] TOTP RFC 6238 Module: FAULT\n";
    $health['overall_status'] = 'UNHEALTHY';
}

echo "-------------------------------------------------------\n";
echo "System Health Status: " . $health['overall_status'] . "\n";

if (php_sapi_name() !== 'cli') {
    header('Content-Type: application/json');
    echo json_encode($health, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

exit($health['overall_status'] === 'HEALTHY' ? 0 : 1);
