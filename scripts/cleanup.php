<?php
/**
 * ============================================================================
 *  scripts/cleanup.php — AUTOMATED DATA RETENTION & TOKEN PURGE UTILITY
 * ============================================================================
 *  Cleans expired password reset tokens, temporary OTP verification hashes,
 *  stale rate-limit locks, and security audit logs older than 90 days.
 *  Recommended Cron Execution: Daily at midnight (`0 0 * * *`).
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

// Prevent direct unauthenticated web execution
if (php_sapi_name() !== 'cli') {
    require_permission('manage_settings');
}

purge_expired_tokens_and_logs($conn);

log_security_event('DATA_RETENTION_CLEANUP_EXECUTED', ['status' => 'completed'], $_SESSION['user_id'] ?? null, 'INFO');

if (php_sapi_name() === 'cli') {
    echo "Data retention cleanup completed successfully.\n";
} else {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success' => true,
        'message' => 'Data retention and token purge completed successfully.'
    ], JSON_UNESCAPED_SLASHES);
}
