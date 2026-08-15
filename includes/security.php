<?php
/**
 * ============================================================================
 *  includes/security.php — MASTER SECURITY INITIATOR & MODULE BOOTSTRAPPER
 * ============================================================================
 *  Imports and bootstraps all modular security subsystems:
 *    - Session management (`session.php`)
 *    - Database connection (`database.php`)
 *    - Error handling & Security logging (`error_handler.php`, `logger.php`)
 *    - Synchronizer CSRF tokens (`csrf.php`)
 *    - Persistent Rate Limiting (`rate_limit.php`)
 *    - Role-Based Access Control & Impersonation (`authorization.php`)
 *    - API Authentication & CORS (`api_auth.php`)
 *    - Security Headers & CSP (`headers.php`)
 *    - Field-Level Encryption (`encryption.php`)
 *    - Schema Validation (`validation.php`)
 * ============================================================================
 */

require_once __DIR__ . '/../config/session.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/rate_limit.php';
require_once __DIR__ . '/authorization.php';
require_once __DIR__ . '/api_auth.php';
require_once __DIR__ . '/headers.php';
require_once __DIR__ . '/encryption.php';
require_once __DIR__ . '/validation.php';

// Automatically dispatch hardened security HTTP headers
send_security_headers(true);

/**
 * Global Output Escaping Helper (XSS Protection).
 */
if (!function_exists('e')) {
    function e(?string $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
    }
}
