<?php
/**
 * ============================================================================
 *  includes/csrf.php — SYNCHRONIZER CSRF TOKEN PROTECTION
 * ============================================================================
 *  Provides cryptographically secure CSRF protection using timing-safe
 *  `hash_equals()` comparison.
 * ============================================================================
 */

/**
 * Returns the current CSRF token for the active session, generating one if needed.
 */
function csrf_token(): string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Returns a ready-to-print hidden HTML input tag for forms.
 */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

/**
 * Timing-safe CSRF token verification.
 */
function verify_csrf(string $submitted): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (empty($_SESSION['csrf_token']) || trim($submitted) === '') {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], trim($submitted));
}
