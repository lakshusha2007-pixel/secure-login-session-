<?php
/**
 * ============================================================================
 *  logout.php — COMPLETE, SECURE LOGOUT
 * ============================================================================
 *
 *  Order of operations:
 *      1. Start the session (needed to destroy it).
 *      2. Delete the session cookie from the browser (setcookie with a past
 *         expiry time, same parameters as when it was created).
 *      3. session_unset()  — wipe all session data.
 *      4. session_destroy()— destroy the server-side session.
 *      5. Redirect to login.php and exit immediately.
 *
 *  Why every step matters:
 *      - session_unset() + session_destroy() ensure NO trace of the identity
 *        remains on the server, so the dashboard is unreachable afterwards.
 *      - Deleting the cookie stops the browser from resurrecting the session.
 *
 *  CSRF note:
 *      The dashboard always submits this page via a POST form carrying a CSRF
 *      token. If the token is missing/invalid we still log the user out,
 *      because logging out is a harmless, idempotent action — an attacker
 *      "forcing" a logout is at worst an annoyance, and refusing to log out
 *      a legitimate user would be worse.
 * ============================================================================
 */

// Load the secure session configuration + helpers.
require_once __DIR__ . '/includes/auth.php';

// --- Log security event ------------------------------------------------------
if (isset($_SESSION['user_id'])) {
    log_security_event('LOGOUT', ['user_id' => $_SESSION['user_id'], 'email' => $_SESSION['email'] ?? ''], (int)$_SESSION['user_id'], 'INFO');
}

// --- Delete the session cookie ------------------------------------------------
// Rebuild the exact same parameters the cookie was set with, but with a
// timestamp in the PAST so the browser removes it immediately. Using the
// options-array form lets us repeat the SameSite attribute too.
$params = session_get_cookie_params();
setcookie(session_name(), '', [
    'expires'  => time() - 42000,           // expires in the past -> deleted
    'path'     => $params['path'],
    'domain'   => $params['domain'],
    'secure'   => $params['secure'],
    'httponly' => $params['httponly'],
    'samesite' => $params['samesite'] ?? 'Lax',
]);

// --- Destroy the server-side session -----------------------------------------
// Clear every value stored in $_SESSION ...
$_SESSION = [];

// ... wipe the session data file ...
session_unset();

// ... and destroy the session completely.
session_destroy();

// --- Redirect ----------------------------------------------------------------
// The "logged_out=1" flag lets login.php show a friendly "signed out" banner.
header('Location: login.php?logged_out=1');
exit;
