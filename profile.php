<?php
/**
 * ============================================================================
 *  profile.php — USER PROFILE & ACCOUNT MANAGEMENT
 * ============================================================================
 *  Displays Profile Name, Email, Verification Status badge, and Google Connected status.
 *  Allows logged-in users to update their profile display name securely.
 *  Hides internal IDs, tokens, password hashes, and security metadata.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Require user to be logged in
require_login();

// 2.1 Object-Level Authorization / IDOR Prevention:
// Check requested user ID in GET parameter (e.g. profile.php?id=3).
// Never trust GET/POST user IDs. Only allow if current session owns resource or is Admin.
$targetUserId = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];
if (!can_access_user_resource($targetUserId)) {
    log_security_event('IDOR_ATTEMPT_BLOCKED', [
        'session_user_id' => $_SESSION['user_id'],
        'requested_id'   => $targetUserId,
        'uri'            => $_SERVER['REQUEST_URI'] ?? ''
    ], (int)$_SESSION['user_id'], 'ALERT');

    http_response_code(403);
    require_once __DIR__ . '/403.php';
    exit;
}

$userId     = $targetUserId;
$error      = '';
$successMsg = '';

// Read Flash Messages
if (isset($_SESSION['flash_success'])) {
    $successMsg = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}
if (isset($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}

// Fetch target user details from database
$stmt = $conn->prepare('SELECT fullname, email, phone, phone_encrypted, email_verified, google_id, mfa_enabled, avatar FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $userId);
$stmt->execute();
$userProfile = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$userProfile) {
    header('Location: logout.php');
    exit;
}

// Decrypt sensitive PII if present
$displayPhone = !empty($userProfile['phone_encrypted']) ? decrypt_pii($userProfile['phone_encrypted']) : ($userProfile['phone'] ?? '');

// Handle Profile Update Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($_POST['action']) || $_POST['action'] === 'update_profile')) {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $newFullname = trim($_POST['fullname'] ?? '');
        $newPhone    = trim($_POST['phone'] ?? '');

        // Security check: Ignore any client-supplied 'role' field (Prevent self-role modification)

        if ($newFullname === '') {
            $error = 'Profile name cannot be empty.';
        } elseif (!validate_name_length($newFullname)) {
            $error = 'Profile name must be between 3 and 20 characters long.';
        } else {
            // Encrypt sensitive PII at rest using AES-256-GCM
            $encryptedPhone = encrypt_pii($newPhone);

            // Prepared SQL Statement: update authenticated target user's details
            $stmt = $conn->prepare('UPDATE users SET fullname = ?, phone = ?, phone_encrypted = ? WHERE id = ?');
            $stmt->bind_param('sssi', $newFullname, $newPhone, $encryptedPhone, $userId);

            if ($stmt->execute()) {
                $stmt->close();

                log_security_event('PROFILE_UPDATED', ['user_id' => $userId, 'new_fullname' => $newFullname], $userId, 'INFO');

                // Update session state if modifying own profile
                if ($userId === (int)$_SESSION['user_id']) {
                    $_SESSION['fullname'] = $newFullname;
                }

                $userProfile['fullname']        = $newFullname;
                $userProfile['phone']           = $newPhone;
                $userProfile['phone_encrypted'] = $encryptedPhone;
                $displayPhone                   = $newPhone;

                $successMsg = 'Profile updated successfully!';
            } else {
                $stmt->close();
                log_security_event('PROFILE_UPDATE_FAILED', ['user_id' => $userId], $userId, 'WARNING');
                $error = 'Failed to update profile. Please try again.';
            }
        }
    }
}

$pageTitle = 'My Profile — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide">
    <h2>Profile Settings</h2>
    <p class="card-sub">Manage your account information, display name, avatar, and multi-factor authentication.</p>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <!-- Avatar Display & Secure Upload Form -->
    <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap;">
        <div style="width: 80px; height: 80px; border-radius: 50%; overflow: hidden; background: #e2e8f0; border: 2px solid var(--primary); display: flex; align-items: center; justify-content: center; font-size: 2rem;">
            <?php if (!empty($userProfile['avatar']) && file_exists(__DIR__ . '/' . $userProfile['avatar'])): ?>
                <img src="<?php echo e($userProfile['avatar']); ?>" alt="Profile Avatar" style="width: 100%; height: 100%; object-fit: cover;">
            <?php else: ?>
                👤
            <?php endif; ?>
        </div>
        <div style="flex: 1;">
            <div style="font-weight: 700; color: var(--text-dark); margin-bottom: 0.25rem;">Profile Avatar (Secure Upload)</div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">Allowed: JPG, PNG, WEBP. Max size: 2 MB. Server-side MIME &amp; double-extension verified.</div>
            <form method="post" action="api/upload_avatar.php" enctype="multipart/form-data" style="display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin: 0;">
                <?php echo csrf_field(); ?>
                <input type="file" name="avatar" accept="image/jpeg,image/png,image/webp" required style="font-size: 0.85rem;">
                <button type="submit" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;">Upload Avatar</button>
            </form>
        </div>
    </div>


    <!-- Profile Status Summary Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="info-card">
            <div class="label">Email Verification</div>
            <?php if ((int)$userProfile['email_verified'] === 1): ?>
                <span class="status-badge success">Verified</span>
            <?php else: ?>
                <span class="status-badge warning">Unverified</span>
            <?php endif; ?>
        </div>

        <div class="info-card">
            <div class="label">2FA / MFA Status</div>
            <?php if ((int)($userProfile['mfa_enabled'] ?? 0) === 1): ?>
                <span class="status-badge success">🔐 Active</span>
            <?php else: ?>
                <span class="status-badge warning">⚠️ Disabled</span>
            <?php endif; ?>
        </div>

        <div class="info-card">
            <div class="label">Google Single Sign-On</div>
            <?php if (!empty($userProfile['google_id'])): ?>
                <span class="status-badge success">Connected</span>
            <?php else: ?>
                <span class="role-badge" style="background: var(--bg-app); color: var(--text-muted);">Not Connected</span>
            <?php endif; ?>
        </div>
    </div>

    <!-- Quick Security Link -->
    <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
            <div style="font-weight: 700; color: var(--text-dark);">🔐 Multi-Factor Authenticator Setup</div>
            <div style="font-size: 0.85rem; color: var(--text-muted);">Secure your account with Google Authenticator or Authy TOTP app.</div>
        </div>
        <div>
            <a href="mfa_enroll.php" class="btn btn-secondary" style="padding: 0.45rem 1rem; font-size: 0.85rem;">Manage MFA &rarr;</a>
        </div>
    </div>

    <form id="profile-form" method="post" action="profile.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address -->
        <div class="form-group">
            <label>Registered Email Address</label>
            <div style="display: flex; gap: 0.5rem;">
                <input class="form-control" type="text" value="<?php echo e($userProfile['email']); ?>" disabled readonly style="background: var(--bg-app); color: var(--text-muted); cursor: not-allowed; flex: 1;">
                <a href="change_email.php" class="btn btn-secondary" style="width: auto; font-size: 0.85rem; padding: 0.5rem 0.85rem; white-space: nowrap;">Change Email</a>
            </div>
        </div>


        <!-- Full Name / Username -->
        <div class="form-group">
            <label for="fullname">Display Name <span style="font-weight:normal; color:var(--text-muted);">(3-20 characters)</span></label>
            <input class="form-control" type="text" id="fullname" name="fullname"
                   value="<?php echo e($userProfile['fullname']); ?>"
                   required minlength="3" maxlength="20">
        </div>

        <!-- Phone Number (PII Encrypted at Rest) -->
        <div class="form-group">
            <label for="phone">Phone Number <span style="font-weight:normal; color:var(--text-muted);">(Stored Encrypted at Rest 🔒)</span></label>
            <input class="form-control" type="text" id="phone" name="phone"
                   value="<?php echo e($displayPhone); ?>"
                   maxlength="20">
        </div>

        <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem; flex-wrap: wrap;">
            <button type="submit" class="btn btn-primary" style="width: auto;">Save Changes</button>
            <a href="change_password.php" class="btn btn-secondary" style="width: auto;">🔑 Change Password</a>
            <a class="btn" href="dashboard.php" style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); text-decoration: none;">Back to Dashboard</a>
        </div>

    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

