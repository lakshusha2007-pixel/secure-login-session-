<?php
/**
 * ============================================================================
 *  dashboard.php — PROTECTED USER DASHBOARD
 * ============================================================================
 *  Requires authentication. Displays user welcome information and account details.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_login();

$pageTitle = 'Dashboard — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide">
    <!-- Success Login Alert Banner -->
    <div class="alert alert-success" style="margin-bottom: 1.5rem;">
        ✅ <strong><?php echo e($_SESSION['fullname']); ?></strong> successfully logged in!
    </div>

    <!-- Welcome Banner -->
    <div class="welcome-banner">
        <h2>🎉 Welcome back, <?php echo e($_SESSION['fullname']); ?>!</h2>
        <p><strong><?php echo e($_SESSION['fullname']); ?></strong> successfully logged into the secure login &amp; session management system.</p>
    </div>

    <!-- Account Details Grid -->
    <div class="info-grid" style="margin-bottom: 2rem;">
        <div class="info-card">
            <div class="label">Full Name</div>
            <div class="value"><?php echo e($_SESSION['fullname']); ?></div>
        </div>
        <div class="info-card">
            <div class="label">Email Address</div>
            <div class="value"><?php echo e($_SESSION['email']); ?></div>
        </div>
    </div>

    <!-- Quick Access Feature Cards -->
    <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-bottom: 2rem;">
        <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
            <div>
                <div style="font-weight: 700; font-size: 1rem; margin-bottom: 0.3rem; color: var(--primary);">👤 Profile &amp; Security Settings</div>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0;">Update personal details, change password, manage MFA, or export account data.</p>
            </div>
            <a href="profile.php" class="btn btn-primary" style="font-size: 0.85rem; padding: 0.45rem 1rem; white-space: nowrap;">Manage Profile &amp; Security &rarr;</a>
        </div>
    </div>

    <!-- Actions Row -->
    <div class="logout-row" style="display: flex; gap: 1rem; justify-content: flex-end; align-items: center; border-top: 1px solid var(--border); padding-top: 1.5rem; flex-wrap: wrap;">
        <?php if (is_admin()): ?>
            <a class="btn btn-secondary" href="admin/index.php" style="width: auto; min-width: 170px;">⚙️ Admin Control Center</a>
        <?php endif; ?>
        <a class="btn" href="privacy.php" style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); text-decoration: none;">📋 Privacy Policy</a>
        <a class="btn btn-primary" href="profile.php" style="width: auto; min-width: 150px;">✏️ Edit Profile</a>
        <form id="logout-form" method="post" action="logout.php" style="margin:0;">
            <?php echo csrf_field(); ?>
            <button type="submit" class="btn btn-danger" style="width: auto; min-width: 130px;">🚪 Logout</button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
