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
        <p>You are viewing a page that is protected by server-side session authentication.</p>
    </div>

    <!-- Key account information -->
    <div class="info-grid">
        <div class="info-card">
            <div class="label">User ID</div>
            <div class="value"><?php echo e((string) $_SESSION['user_id']); ?></div>
        </div>
        <div class="info-card">
            <div class="label">Full Name / Username</div>
            <div class="value"><?php echo e($_SESSION['fullname']); ?></div>
            <small style="color: var(--text-muted); font-size:0.75rem;">(Length: <?php echo mb_strlen($_SESSION['fullname']); ?> chars)</small>
        </div>
        <div class="info-card">
            <div class="label">Email Address</div>
            <div class="value"><?php echo e($_SESSION['email']); ?></div>
        </div>
        <div class="info-card">
            <div class="label">Phone Number</div>
            <div class="value"><?php echo e($_SESSION['phone'] ?? '+919876543210'); ?></div>
        </div>
        <div class="info-card">
            <div class="label">Role</div>
            <div class="value"><span class="role-badge"><?php echo e($_SESSION['role']); ?></span></div>
        </div>
        <div class="info-card">
            <div class="label">Session ID (Regenerated at Login)</div>
            <div class="value mono"><?php echo e(session_id()); ?></div>
        </div>
    </div>

    <!-- Educational session metadata -->
    <div class="session-meta">
        <strong>Active Security Defences on Your Session:</strong><br>
        &#10003; Full Name / Username length enforced (12 to 15 characters)<br>
        &#10003; Password strength rules enforced (min 8 chars, uppercase, lowercase, number, special char)<br>
        &#10003; Passwords stored as salted Bcrypt hashes using <code>password_hash()</code><br>
        &#10003; Session ID regenerated post-login (<code>session_regenerate_id()</code>)<br>
        &#10003; Hardened Cookies (<code>HttpOnly</code> + <code>Secure</code> + <code>SameSite=Lax</code>)<br>
        &#10003; Automatic sliding 30-minute idle session expiry<br>
        &#10003; All output escaped with <code>htmlspecialchars()</code>
    </div>

    <div class="logout-row">
        <form id="logout-form" method="post" action="logout.php">
            <?php echo csrf_field(); ?>
            <button type="submit" class="btn btn-danger">&#10162; Logout</button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
