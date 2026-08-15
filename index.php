<?php
/**
 * ============================================================================
 *  index.php — LANDING / HOME PAGE
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Logged-in users go straight to the dashboard.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$pageTitle = 'Secure Login & Session Protection';
require_once __DIR__ . '/includes/header.php';
?>

<section class="hero text-center" style="max-width: 760px; margin: 0 auto; padding: 2rem 0;">
    <h1 class="page-title" style="font-size: 2.5rem; line-height: 1.25; margin-bottom: 0.75rem;">
        Secure Login &amp; Session Management
    </h1>
    <p class="page-subtitle" style="margin: 0 auto 2.2rem auto; font-size: 1.05rem; color: var(--text-muted);">
        A production-ready authentication system built with Core PHP 8+, MySQL, Session Security, and Google OAuth 2.0.
    </p>

    <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
        <a class="btn btn-primary cta-btn" href="login.php">Sign In to Account &rarr;</a>
        <a class="btn cta-btn" style="background: #ffffff; border: 1px solid var(--border); color: var(--text-main);" href="register.php">Create Account</a>
    </div>
</section>

<section class="features">
    <div class="feature">
        <h3><span>🔒</span> Password Hashing</h3>
        <p>Passwords are stored securely as salted bcrypt hashes using PHP's <code>password_hash()</code>. Plaintext passwords are never saved.</p>
    </div>
    <div class="feature">
        <h3><span>📩</span> Email OTP &amp; OAuth</h3>
        <p>Supports 6-digit email OTP verification codes and Google OAuth 2.0 single sign-on integration.</p>
    </div>
    <div class="feature">
        <h3><span>🛡️</span> Session Safeguards</h3>
        <p>Session IDs are regenerated post-login to prevent fixation attacks. Cookies are hardened with <code>HttpOnly</code> and <code>SameSite=Lax</code>.</p>
    </div>
    <div class="feature">
        <h3><span>🚨</span> Brute-Force Lockout</h3>
        <p>Automated threat detection locks accounts after repeated failed logins to block dictionary and brute-force attacks.</p>
    </div>
</section>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
