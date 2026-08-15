<?php
/**
 * ============================================================================
 *  privacy.php — PRIVACY POLICY & COOKIE DISCLOSURE PAGE
 * ============================================================================
 *  Section 3.5.1 Compliance & Privacy:
 *  Transparently details personal data collection, cookie usage, session storage,
 *  and audit log retention policies.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

$pageTitle = 'Privacy Policy & Cookie Disclosure — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide" style="max-width: 800px; margin: 2rem auto;">
    <h2>📋 Privacy Policy &amp; Cookie Disclosure</h2>
    <p class="card-sub">Information about how we collect, store, and protect your personal data and authentication cookies.</p>

    <div style="line-height: 1.7; color: var(--text-dark); font-size: 0.95rem;">
        <h3 style="color: var(--primary); margin-top: 1.5rem; margin-bottom: 0.5rem;">1. Information We Collect</h3>
        <p>
            To provide secure user authentication and access control, our application collects the following strictly necessary information:
        </p>
        <ul style="margin-left: 1.5rem; margin-bottom: 1rem;">
            <li><strong>Email Address &amp; Display Name:</strong> Used as your unique account identity and for sending verification/reset OTP codes.</li>
            <li><strong>Phone Number (Optional):</strong> Encrypted at rest using authenticated AES-256-GCM encryption.</li>
            <li><strong>IP Address &amp; User-Agent:</strong> Logged automatically during authentication attempts to enforce rate limiting, brute-force protection, and security incident audits.</li>
        </ul>

        <h3 style="color: var(--primary); margin-top: 1.5rem; margin-bottom: 0.5rem;">2. Authentication &amp; Session Cookies</h3>
        <p>
            We use strictly necessary first-party session cookies to keep you signed in securely. We do <strong>NOT</strong> use any third-party tracking, advertising, or profiling cookies.
        </p>
        <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0;">
            <table style="width: 100%; border-collapse: collapse; font-size: 0.88rem;">
                <thead>
                    <tr style="border-bottom: 2px solid var(--border); text-align: left;">
                        <th style="padding: 0.5rem;">Cookie Name</th>
                        <th style="padding: 0.5rem;">Security Flags</th>
                        <th style="padding: 0.5rem;">Purpose</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="padding: 0.5rem; font-family: monospace; font-weight: 700;">SECURE_SESSION</td>
                        <td style="padding: 0.5rem;"><code>HttpOnly</code>, <code>Secure</code>, <code>SameSite=Lax</code></td>
                        <td style="padding: 0.5rem;">Stores your encrypted session ID server-side. Lifetime expires when browser closes.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <h3 style="color: var(--primary); margin-top: 1.5rem; margin-bottom: 0.5rem;">3. Data Retention &amp; Deletion</h3>
        <p>
            Expired email verification tokens, password reset OTP codes, and rate limit records are automatically purged. Security audit logs are retained for up to 90 days for incident analysis and then deleted.
        </p>
        <p>
            Logged-in users have full rights to export their stored personal data (DSAR JSON export) or permanently delete their account at any time via <a href="profile.php" style="color: var(--primary);">Profile Settings</a>.
        </p>
    </div>

    <div style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem; text-align: right;">
        <a href="index.php" class="btn btn-secondary">&larr; Return to Home</a>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
