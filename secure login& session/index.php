<?php
/**
 * ============================================================================
 *  index.php — LANDING / HOME PAGE
 * ============================================================================
 *  A public marketing-style page describing the system.
 *
 *  Flow:
 *      - Visitors see the landing page with a short feature list and a
 *        "Login" call-to-action.
 *      - Already-logged-in users are sent straight to the dashboard.
 * ============================================================================
 */

// Load the auth helpers (starts the secure session + DB connection).
require_once __DIR__ . '/includes/auth.php';

// Logged-in users don't need the landing page — go to the dashboard.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

// Title used by the shared header.
$pageTitle = 'Home — Secure Login System';

// Output the HTML head + navigation (requires header.php AFTER the redirects
// above, because header() must run before any output).
require_once __DIR__ . '/includes/header.php';
?>

<section class="hero text-center">
    <h1 class="page-title">Secure Login &amp; Session Management</h1>
    <p class="page-subtitle">
        A production-ready authentication demo built with Core PHP, PHP Sessions,
        MySQL, HTML5, CSS3 and Vanilla JavaScript &mdash; no frameworks.
    </p>

    <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
        <a class="btn btn-primary cta-btn" href="login.php">Sign In</a>
        <a class="btn nav-btn cta-btn" style="background: rgba(255,255,255,0.15); border: 1px solid rgba(255,255,255,0.3);" href="setup_check.php">&#128736; Setup &amp; Diagnostics</a>
    </div>
</section>

<section class="features">
    <div class="feature">
        <h3>&#128274; Secure Passwords</h3>
        <p>Passwords are stored only as salted bcrypt hashes using PHP's
        <code>password_hash()</code> &mdash; plain text is never kept.</p>
    </div>
    <div class="feature">
        <h3>&#128737; Session Protection</h3>
        <p>Session IDs are regenerated after login to defeat fixation, and the
        cookie is <code>HttpOnly</code>, <code>Secure</code> and
        <code>SameSite=Lax</code>.</p>
    </div>
    <div class="feature">
        <h3>&#128273; Brute-Force Resistance</h3>
        <p>After 5 failed attempts for the same email, login locks for 5 minutes
        &mdash; slowing automated guessing attacks.</p>
    </div>
    <div class="feature">
        <h3>&#128680; SQL Injection &amp; XSS Proof</h3>
        <p>All database queries use prepared statements, and every output is
        escaped with <code>htmlspecialchars()</code>.</p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
