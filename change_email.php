<?php
/**
 * ============================================================================
 *  change_email.php — SENSITIVE EMAIL CHANGE WITH RE-AUTHENTICATION
 * ============================================================================
 *  Requires authentication (require_login()) AND Step-Up (require_step_up()).
 *  1. Validates new email format and checks for duplicate registrations.
 *  2. Sends 6-digit OTP verification code to the new email address.
 *  3. Sends security warning alert to the current/old email address.
 *  4. Updates account email only after successful OTP verification.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_login();
require_step_up(); // Enforce Step-Up password re-verification

$userId   = (int)$_SESSION['user_id'];
$error    = '';
$success  = '';
$pending  = $_SESSION['pending_email_change'] ?? null;

// Handle New Email Request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request_email_change') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $newEmail = strtolower(trim($_POST['new_email'] ?? ''));

        if (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } elseif ($newEmail === strtolower($_SESSION['email'])) {
            $error = 'New email address must be different from your current email.';
        } else {
            // Check if email already registered
            $stmt = $conn->prepare('SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1');
            $stmt->bind_param('si', $newEmail, $userId);
            $stmt->execute();
            $exists = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if ($exists) {
                $error = 'Email address is already in use by another account.';
            } else {
                // Generate 6-digit OTP and store hash in session
                $otp = sprintf('%06d', random_int(0, 999999));
                $otpHash = password_hash($otp, PASSWORD_DEFAULT);

                $_SESSION['pending_email_change'] = [
                    'new_email'  => $newEmail,
                    'otp_hash'   => $otpHash,
                    'expires_at' => time() + 600 // 10 minutes
                ];
                $pending = $_SESSION['pending_email_change'];

                // 1. Send OTP to New Email Address
                send_security_notification_email(
                    $newEmail,
                    $_SESSION['fullname'],
                    'Email Change Verification Code',
                    "Hello " . e($_SESSION['fullname']) . ",\n\nYour 6-digit verification code to confirm changing your account email is: $otp\n\nThis code expires in 10 minutes.\n\nSecureAuth Security Team"
                );

                // 2. Send Security Warning Alert to Old Email Address
                send_security_notification_email(
                    $_SESSION['email'],
                    $_SESSION['fullname'],
                    'Security Alert: Email Change Requested',
                    "Hello " . e($_SESSION['fullname']) . ",\n\nA request was initiated to change your SecureAuth account email to $newEmail on " . date('Y-m-d H:i:s T') . ".\n\nIf you did not request this change, please log in and change your password immediately."
                );

                log_security_event('EMAIL_CHANGE_REQUESTED', ['user_id' => $userId, 'new_email' => $newEmail], $userId, 'INFO');
                $success = "Verification OTP sent to $newEmail. A security alert was also sent to your current email.";
            }
        }
    }
}

// Handle OTP Verification Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'verify_email_otp') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } elseif (!$pending || time() > $pending['expires_at']) {
        unset($_SESSION['pending_email_change']);
        $pending = null;
        $error = 'Verification OTP expired. Please request a new email change.';
    } else {
        $inputOtp = trim($_POST['otp'] ?? '');

        if (password_verify($inputOtp, $pending['otp_hash'])) {
            $oldEmail = $_SESSION['email'];
            $newEmail = $pending['new_email'];

            // Update user email in database
            $upd = $conn->prepare('UPDATE users SET email = ?, email_verified = 1 WHERE id = ?');
            $upd->bind_param('si', $newEmail, $userId);

            if ($upd->execute()) {
                $upd->close();

                $_SESSION['email'] = $newEmail;
                unset($_SESSION['pending_email_change']);
                $pending = null;

                log_security_event('EMAIL_CHANGED_SUCCESS', ['user_id' => $userId, 'old_email' => $oldEmail, 'new_email' => $newEmail], $userId, 'INFO');

                $success = "Your account email address has been updated successfully to $newEmail!";
            } else {
                $upd->close();
                $error = 'Failed to update email. Please try again.';
            }
        } else {
            log_security_event('EMAIL_CHANGE_OTP_INVALID', ['user_id' => $userId], $userId, 'WARNING');
            $error = 'Invalid verification code. Please check your email and try again.';
        }
    }
}

$pageTitle = 'Change Email Address — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="max-width: 520px; margin: 2rem auto;">
    <h2>📧 Change Email Address</h2>
    <p class="card-sub">Update your account email address with 2-step verification.</p>

    <?php if ($success !== ''): ?>
        <div class="alert alert-success"><?php echo e($success); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <?php if ($pending): ?>
        <!-- Step 2: OTP Verification Form -->
        <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-size: 0.9rem; color: var(--text-dark); margin-bottom: 0.5rem;">
                Verification code sent to: <strong><?php echo e($pending['new_email']); ?></strong>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted);">
                Check your inbox (and spam folder) for the 6-digit verification code.
            </div>
        </div>

        <form method="post" action="change_email.php" autocomplete="off">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="verify_email_otp">

            <div class="form-group">
                <label for="otp">6-Digit Verification Code</label>
                <input class="form-control" type="text" id="otp" name="otp" required autofocus pattern="[0-9]{6}" maxlength="6"
                       style="font-size: 1.5rem; letter-spacing: 6px; text-align: center; font-weight: 700;" placeholder="000000">
            </div>

            <button type="submit" class="btn btn-primary" style="width: 100%;">Verify &amp; Update Email &rarr;</button>
        </form>
    <?php else: ?>
        <!-- Step 1: Enter New Email Form -->
        <form method="post" action="change_email.php" autocomplete="off">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="request_email_change">

            <div class="form-group">
                <label>Current Email Address</label>
                <input class="form-control" type="text" value="<?php echo e($_SESSION['email']); ?>" disabled readonly style="background: var(--bg-app); color: var(--text-muted); cursor: not-allowed;">
            </div>

            <div class="form-group">
                <label for="new_email">New Email Address</label>
                <input class="form-control" type="email" id="new_email" name="new_email" required autofocus placeholder="newuser@example.com">
            </div>

            <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem; flex-wrap: wrap;">
                <button type="submit" class="btn btn-primary" style="width: auto;">Send Verification Code &rarr;</button>
                <a href="profile.php" class="btn" style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); text-decoration: none;">Back to Profile</a>
            </div>
        </form>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
