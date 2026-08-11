<?php
/**
 * ============================================================================
 *  includes/header.php — SHARED HTML HEAD + TOP NAVIGATION + SECURITY HEADERS
 * ============================================================================
 *
 *  Include this file at the top of any full page, AFTER you have already
 *  required includes/auth.php (so the session is running and $pageTitle is
 *  optional).
 *
 *  Usage pattern:
 *      $pageTitle = 'Login';
 *      require_once __DIR__ . '/includes/auth.php';
 *      require_once __DIR__ . '/includes/header.php';
 * ============================================================================
 */

// Security HTTP headers (must be sent before ANY HTML output).
// -----------------------------------------------------------------------------
// X-Frame-Options: SAMEORIGIN — stops other websites from embedding our pages
// in <iframe>s (blocks "clickjacking" attacks).
header('X-Frame-Options: SAMEORIGIN');

// X-Content-Type-Options: nosniff — forces the browser to use the MIME type we
// declare, instead of guessing. Prevents certain drive-by download attacks.
header('X-Content-Type-Options: nosniff');

// Referrer-Policy: no-referrer — our page never leaks the previous URL / query
// strings (which could contain sensitive tokens) to other sites.
header('Referrer-Policy: no-referrer');

// Cache-Control: no-store — tells the browser NEVER to cache these pages.
// Why: after logout, pressing the browser Back button must NOT show a stale
// copy of the dashboard. With no-store, Back goes to login.php instead.
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Content-Security-Policy — whitelists what the browser may load
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; form-action 'self' https:; base-uri 'self'; frame-ancestors 'self'");
// -----------------------------------------------------------------------------

// Default page title if the including page did not set one.
$pageTitle = $pageTitle ?? 'Secure Login System';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo e($pageTitle); ?></title>

    <!-- Only our own stylesheet -->
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>

<header class="site-header">
    <div class="container nav-wrap">
        <!-- Brand / logo -->
        <a class="brand" href="index.php">
            <span class="brand-badge">&#128274;</span> SecureAuth
        </a>

        <!-- Navigation links -->
        <nav class="nav">
            <a href="index.php">Home</a>

            <?php if (is_logged_in()): ?>
                <a href="dashboard.php">Dashboard</a>
                <a href="profile.php">Profile</a>
                <a class="nav-btn" href="logout.php">Logout</a>
            <?php else: ?>
                <a href="register.php">Register</a>
                <a class="nav-btn" href="login.php">Login</a>
            <?php endif; ?>
        </nav>
    </div>
</header>

<main class="container">
