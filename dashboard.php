<?php
/**
 * ============================================================================
 *  dashboard.php — PROTECTED DASHBOARD
 * ============================================================================
 *
 *  Access rules:
 *      - ONLY authenticated users may see this page.
 *      - Guests are redirected to login.php immediately (require_login()).
 *
 *  Displayed information:
 *      - Welcome banner with user's full name
 *      - User ID, Email, Phone Number, Role
 *      - Session ID (regenerated on login)
 * ============================================================================
 */

// Require the auth helpers (starts session + DB).
require_once __DIR__ . '/includes/auth.php';

// If the visitor is not logged in, send them to login.php immediately.
require_login();

$pageTitle = 'Dashboard — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide">
    <!-- Welcome banner -->
    <div class="welcome-banner">
        <h2>&#127881; Welcome, <?php echo e($_SESSION['fullname']); ?>!</h2>
        <p>You are logged in to your secure account dashboard.</p>
    </div>

    <!-- Key account information -->
    <div class="info-grid">
        <div class="info-card">
            <div class="label">Name</div>
            <div class="value"><?php echo e($_SESSION['fullname']); ?></div>
        </div>
        <!-- <div class="info-card">
            <div class="label">User ID</div>
            <div class="value"><?php echo e((string) $_SESSION['user_id']); ?></div>
        </div> -->
        <!-- <div class="info-card">
            <div class="label">Role</div>
            <div class="value"><span class="role-badge"><?php echo e($_SESSION['role']); ?></span></div>
        </div> -->
        <!-- <div class="info-card">
            <div class="label">Session ID</div>
            <div class="value mono"><?php echo e(session_id()); ?></div>
        </div> -->
        <!-- <div class="info-card">
            <div class="label">Email Address</div>
            <div class="value"><?php echo e($_SESSION['email']); ?></div>
        </div> -->
    </div>

    <!-- Security Defences Overview -->
    <div class="session-meta">
        <strong>Active Security Defences on Your Session:</strong><br>
        &#10003; Email Verification &amp; Google OAuth 2.0 Integration<br>
        &#10003; Passwords stored as salted Bcrypt hashes using <code>password_hash()</code><br>
        &#10003; Session ID regenerated post-login (<code>session_regenerate_id()</code>)<br>
        &#10003; Hardened Cookies (<code>HttpOnly</code> + <code>Secure</code> + <code>SameSite=Lax</code>)<br>
        &#10003; Automatic sliding 30-minute idle session expiry<br>
        &#10003; Output escaped with <code>htmlspecialchars()</code> &amp; Prepared SQL Statements
    </div>

    <div class="logout-row" style="display: flex; gap: 1rem; justify-content: flex-end; align-items: center;">
        <a class="btn btn-primary" href="profile.php">&#9998; Change Profile Name</a>
        <form id="logout-form" method="post" action="logout.php" style="margin:0;">
            <?php echo csrf_field(); ?>
            <button type="submit" class="btn btn-danger">&#10162; Logout</button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
