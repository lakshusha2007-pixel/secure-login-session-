<?php
/**
 * ============================================================================
 *  500.php — CUSTOM SECURE 500 INTERNAL SERVER ERROR PAGE
 * ============================================================================
 *  Displays a generic 500 server error page without exposing raw error traces,
 *  file paths, or internal environment configurations.
 * ============================================================================
 */

http_response_code(500);
$pageTitle = '500 Server Error — Secure Login System';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="text-align: center; max-width: 580px; margin: 3rem auto;">
    <div style="font-size: 3.5rem; line-height: 1; margin-bottom: 1rem;">&#9888;</div>
    <h1 style="font-size: 2.2rem; font-weight: 800; color: var(--text-dark); margin-bottom: 0.5rem;">500 — Internal Server Error</h1>
    <p class="card-sub" style="margin-bottom: 2rem;">
        An unexpected error occurred while processing your request. Our technical team has been logged of this incident.
    </p>

    <div style="display: flex; gap: 1rem; justify-content: center;">
        <a href="index.php" class="btn btn-primary">Return to Home</a>
        <?php if (is_logged_in()): ?>
            <a href="dashboard.php" class="btn btn-secondary">Go to Dashboard</a>
        <?php else: ?>
            <a href="login.php" class="btn btn-secondary">Sign In</a>
        <?php endif; ?>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
