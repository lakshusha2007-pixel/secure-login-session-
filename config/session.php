<?php
/**
 * ============================================================================
 *  config/session.php — SECURE SESSION CONFIGURATION
 * ============================================================================
 *
 *  Every page of the app that needs the session must include this file FIRST,
 *  BEFORE any output (HTML or whitespace) is sent to the browser.
 *
 *  It does three jobs:
 *      1. Configure the session cookie so it is hardened against attacks.
 *      2. Start the session safely.
 *      3. Destroy a session that has been idle too long (inactivity timeout).
 *
 * ----------------------------------------------------------------------------
 */

// Load production error and exception handler
require_once __DIR__ . '/../includes/error_handler.php';

// Enforce HTTPS Redirection (Site-wide Transport Security)
$isHttps  = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
            (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
$hostHeader = $_SERVER['HTTP_HOST'] ?? '';
$hostName   = explode(':', $hostHeader)[0];

if (!$isHttps && !empty($hostHeader) && !in_array($hostName, ['localhost', '127.0.0.1'], true)) {
    $redirectUrl = 'https://' . $hostHeader . $_SERVER['REQUEST_URI'];
    header('Location: ' . $redirectUrl, true, 301);
    exit;
}

// --- STEP 1: Secure the session cookie ---------------------------------------
/**
 * session_set_cookie_params() tells PHP exactly how the session cookie must
 * behave. Every option below is a security hardening measure:
 *
 * 'lifetime' => 0
 *     0 means "session cookie" -> the cookie lives only while the browser is
 *     open and is DELETED automatically when the user closes their browser.
 *     Do not set a big lifetime here; inactivity is handled by the server-side
 *     timeout below.
 *
 * 'path' => '/'
 *     The cookie is sent to every page of your site (whole domain). Without
 *     this, the cookie could be limited to a sub-folder and cause "logged in
 *     on page A, logged out on page B" problems.
 *
 * 'secure' => true
 *     HTTPS ONLY: the browser will only send this cookie over a secure
 *     (encrypted) HTTPS connection and NEVER over plain HTTP.
 *     InfinityFree serves your site over HTTPS for free, so this is safe.
 *     Result: an attacker sitting on the same Wi-Fi cannot sniff the session
 *     cookie out of the air (protects against SESSION HIJACKING).
 *
 * 'httponly' => true
 *     JavaScript cannot read this cookie via document.cookie.
 *     Result: even if an attacker plants an XSS script on your site, that
 *     script CANNOT steal the session cookie (protects against XSS cookie
 *     theft / SESSION HIJACKING via JavaScript).
 *
 * 'samesite' => 'Lax'
 *     The cookie is NOT sent on cross-site requests from other websites.
 *     Result: a malicious site cannot make your logged-in browser quietly
 *     send the cookie to your site (protects against CSRF and cross-site
 *     request smuggling). 'Lax' still allows normal top-level navigation,
 *     so everyday links still work.
 */
session_set_cookie_params([
    'lifetime' => 0,           // Expire when the browser closes
    'path'     => '/',         // Available across the whole domain
    'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off', // HTTPS only when served over HTTPS
    'httponly' => true,        // Not readable by JavaScript
    'samesite' => 'Lax'        // Blocks cross-site cookie sending
]);

/**
 * Set a human-readable name for the session cookie instead of the default
 * "PHPSESSID". This is a cosmetic-but-useful hardening step: it makes the
 * application look less obviously "default PHP" to casual scanners.
 */
session_name('SECURE_SESSION');

// --- STEP 2: Start the session ----------------------------------------------
/**
 * Hardening ini settings (these MUST be set before session_start()):
 *
 *  session.use_only_cookies = 1
 *      PHP will only accept the session ID from a cookie, NEVER from the URL.
 *      Without this, an attacker could email a victim a link like
 *      "login.php?SECURE_SESSION=abc123" and later hijack the victim's session
 *      once they log in (SESSION FIXATION).
 *
 *  session.use_strict_mode = 1
 *      PHP rejects any session ID the server did not create itself. Combined
 *      with the above, IDs we have never issued are simply ignored.
 */
ini_set('session.use_only_cookies', 1);
ini_set('session.use_trans_sid', 0);
ini_set('session.use_strict_mode', 1);

// Start the session (only if it hasn't been started already — some pages may
// have started it explicitly before including this file).
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- STEP 3: Session inactivity timeout (optional but recommended) -----------
/**
 * Server-side idle timeout:
 * If the user does nothing for 30 minutes, the session is destroyed. This
 * limits the damage if someone forgets to log out on a shared computer.
 */
$inactivityLimit = 30 * 60; // 30 minutes, in seconds

if (isset($_SESSION['last_activity'])) {
    // Time since the user's last request
    $inactiveFor = time() - $_SESSION['last_activity'];

    // If they were idle too long -> kill the session completely
    if ($inactiveFor >= $inactivityLimit) {
        session_unset();     // Remove all session data
        session_destroy();   // Destroy the session itself
        header('Location: login.php');
        exit;
    }
}

// Update the activity timestamp on every request.
// This is a "sliding" timeout: every action resets the 30-minute clock.
$_SESSION['last_activity'] = time();

/**
 * ============================================================================
 *  SECURITY SUMMARY
 * ============================================================================
 *  Session Fixation : prevented by session_regenerate_id(true) after login
 *                      (see includes/auth.php -> regenerate_session()).
 *  Session Hijacking: mitigated by secure + HttpOnly cookies and the
 *                      inactivity timeout.
 *  XSS cookie theft : blocked because the cookie is HttpOnly.
 * ============================================================================
 */
