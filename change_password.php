<?php
/**
 * ============================================================================
 *  change_password.php — AUTHENTICATED SECURE PASSWORD CHANGE
 * ============================================================================
 *  Requires authentication (require_login()).
 *  1. Re-verifies current password via password_verify().
 *  2. Validates new password complexity (8-12+ chars, upper, lower, number, special).
 *  3. Hashes new password using password_hash() (Argon2id/bcrypt).
 *  4. Regenerates session ID (session fixation defense).
 *  5. Sends security notification email via SMTP without including password.
 *  6. Logs security event without secrets.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_login();

$userId = (int)$_SESSION['user_id'];
$error   = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword     = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // 1. Fetch user password hash
        $stmt = $conn->prepare('SELECT fullname, email, password FROM users WHERE id = ? LIMIT 1');
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$user || !password_verify($currentPassword, $user['password'])) {
            log_security_event('PASSWORD_CHANGE_FAILED', ['user_id' => $userId, 'reason' => 'invalid_current_password'], $userId, 'WARNING');
            $error = 'Current password is incorrect.';
        } elseif ($newPassword !== $confirmPassword) {
            $error = 'New password and confirmation password do not match.';
        } elseif (password_verify($newPassword, $user['password'])) {
            $error = 'New password must be different from your current password.';
        } elseif (!validate_password_strength($newPassword)) {
            $error = 'New password does not meet complexity requirements (min 8-12 chars, upper, lower, number, special character).';
        } else {
            // 2. Hash new password using Argon2id / bcrypt
            $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
            $newHash = password_hash($newPassword, $algo);

            // 3. Update database
            $upd = $conn->prepare('UPDATE users SET password = ?, last_password_verified_at = NOW() WHERE id = ?');
            $upd->bind_param('si', $newHash, $userId);

            if ($upd->execute()) {
                $upd->close();

                // 4. Regenerate session ID
                regenerate_session();
                $_SESSION['last_password_verified_at'] = time();

                // 5. Send Security Notification Email via SMTP (Without including the password)
                send_security_notification_email(
                    $user['email'],
                    $user['fullname'],
                    'Password Changed Successfully',
                    "Hello " . e($user['fullname']) . ",\n\nYour account password was successfully updated on " . date('Y-m-d H:i:s T') . " from IP address " . e($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1') . ".\n\nIf you did not initiate this change, please contact support immediately.\n\nSecureAuth Security Team"
                );

                // 6. Log security event without secrets
                log_security_event('PASSWORD_CHANGED_SUCCESS', ['user_id' => $userId], $userId, 'INFO');

                $success = 'Your password has been changed successfully! A security notification email has been sent.';
            } else {
                $upd->close();
                log_security_event('PASSWORD_CHANGE_FAILED', ['user_id' => $userId, 'reason' => 'db_error'], $userId, 'CRITICAL');
                $error = 'Failed to update password. Please try again.';
            }
        }
    }
}

$pageTitle = 'Change Password — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="max-width: 520px; margin: 2rem auto;">
    <h2>🔑 Change Password</h2>
    <p class="card-sub">Update your account password with a strong, unique secret.</p>

    <?php if ($success !== ''): ?>
        <div class="alert alert-success"><?php echo e($success); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form method="post" action="change_password.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <label for="current_password">Current Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="current_password" name="current_password" required autofocus placeholder="••••••••">
                <button type="button" class="toggle-password" data-target="current_password" aria-label="Toggle password visibility">👁️</button>
            </div>
        </div>

        <div class="form-group">
            <label for="new_password">New Password <span style="font-weight:normal; color:var(--text-muted);">(Min 8-12 chars, A-Z, a-z, 0-9, !@#$)</span></label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="new_password" name="new_password" required placeholder="••••••••">
                <button type="button" class="toggle-password" data-target="new_password" aria-label="Toggle password visibility">👁️</button>
            </div>
        </div>

        <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="confirm_password" name="confirm_password" required placeholder="••••••••">
                <button type="button" class="toggle-password" data-target="confirm_password" aria-label="Toggle password visibility">👁️</button>
            </div>
        </div>

        <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem; flex-wrap: wrap;">
            <button type="submit" class="btn btn-primary" style="width: auto;">Update Password &rarr;</button>
            <a href="profile.php" class="btn" style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); text-decoration: none;">Back to Profile</a>
        </div>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
