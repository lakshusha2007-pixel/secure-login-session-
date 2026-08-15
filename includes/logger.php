<?php
/**
 * ============================================================================
 *  includes/logger.php — SECURITY AUDIT LOGGING SYSTEM
 * ============================================================================
 *
 *  Provides a central, hardened security event logger:
 *      - Writes structured JSON entries to append-only logs/security.log file.
 *      - Stores audit records in MySQL `security_logs` database table.
 *      - Records event timestamp, event type, user ID, IP address, User-Agent,
 *        severity level, and contextual details.
 *
 * ============================================================================
 */

require_once __DIR__ . '/../config/database.php';

/**
 * Log a security-relevant event.
 *
 * @param string      $eventType Category/name of security event (e.g. 'LOGIN_SUCCESS', 'LOGIN_FAILED')
 * @param array       $details   Contextual data (e.g. ['email' => 'user@gmail.com', 'reason' => 'invalid_password'])
 * @param int|null    $userId    User ID if available
 * @param string      $severity  Severity level: 'INFO', 'WARNING', 'CRITICAL', 'ALERT'
 * @return bool
 */
function log_security_event(string $eventType, array $details = [], ?int $userId = null, string $severity = 'INFO'): bool
{
    global $conn;

    $timestamp = date('Y-m-d H:i:s');
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    // Mask sensitive fields in details array if inadvertently passed
    $sensitiveKeys = ['password', 'confirm_password', 'token', 'otp', 'reset_token'];
    foreach ($sensitiveKeys as $key) {
        if (isset($details[$key])) {
            $details[$key] = '[REDACTED]';
        }
    }

    $jsonDetails = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    // 1. Write to append-only file logs/security.log
    $logDir = __DIR__ . '/../logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0750, true);
    }

    $logFile = $logDir . '/security.log';
    $logLine = sprintf(
        "[%s] [%s] [IP: %s] [User ID: %s] Event: %s | Details: %s | UA: %s\n",
        $timestamp,
        strtoupper($severity),
        $ipAddress,
        $userId !== null ? (string)$userId : 'N/A',
        $eventType,
        $jsonDetails,
        $userAgent
    );

    @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);

    // 2. Write to MySQL security_logs table
    if ($conn instanceof mysqli && !$conn->connect_error) {
        try {
            $stmt = $conn->prepare('INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details, severity, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())');
            if ($stmt) {
                $stmt->bind_param('isssss', $userId, $eventType, $ipAddress, $userAgent, $jsonDetails, $severity);
                $stmt->execute();
                $stmt->close();
                return true;
            }
        } catch (Throwable $e) {
            // Fallback gracefully if database table issue
            error_log('Failed to insert security log into MySQL: ' . $e->getMessage());
        }
    }

    return true;
}
