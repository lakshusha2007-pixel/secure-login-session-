<?php
/**
 * ============================================================================
 *  404.php — CUSTOM SECURE 404 NOT FOUND PAGE
 * ============================================================================
 *  Displays a generic 404 error without leaking sensitive internal paths
 *  or server architecture details.
 * ============================================================================
 */

http_response_code(404);
$pageTitle = '404 Page Not Found — Secure Login System';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="text-align: center; max-width: 580px; margin: 3rem auto;">
    <div style="font-size: 3.5rem; line-height: 1; margin-bottom: 1rem;">&#128269;</div>
    <h1 style="font-size: 2.2rem; font-weight: 800; color: var(--text-dark); margin-bottom: 0.5rem;">404 — Page Not Found</h1>
    <p class="card-sub" style="margin-bottom: 2rem;">
        The page or resource you requested could not be found. It may have been moved, renamed, or is temporarily unavailable.
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
