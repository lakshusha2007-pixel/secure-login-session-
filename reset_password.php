<?php
/**
 * ============================================================================
 *  reset_password.php — VERIFY OTP & RESET PASSWORD
 * ============================================================================
 *  Verifies single-use 6-digit password reset OTP hash from MySQL.
 *  Enforces password strength rules, hashes password with password_hash(),
 *  and clears single-use reset OTP fields.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$email = trim($_GET['email'] ?? $_POST['email'] ?? '');
$error = '';
$info  = '';

if (isset($_GET['sent'])) {
    $info = 'If an account matches that email address, a 6-digit password reset OTP code has been sent. Please check your inbox.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken  = $_POST['csrf_token'] ?? '';
    $email           = strtolower(trim($_POST['email'] ?? ''));
    $otp             = trim($_POST['otp'] ?? '');
    $password        = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } elseif ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter your email address.';
    } elseif ($otp === '') {
        $error = 'Please enter the 6-digit reset OTP code.';
    } else {
        // Verify 6-digit Reset OTP
        $otpRes = verify_password_reset_otp($email, $otp);

        if (!$otpRes['success']) {
            $error = $otpRes['message'];
        } else {
            $pwdErrors = validate_password_strength($password);

            if (!empty($pwdErrors)) {
                $error = implode(' ', $pwdErrors);
            } elseif ($password !== $confirmPassword) {
                $error = 'Passwords do not match.';
            } else {
                $targetUser = $otpRes['user'];
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                // Update password and clear single-use reset OTP fields
                $updateUser = $conn->prepare('UPDATE users SET password = ?, reset_otp_hash = NULL, reset_otp_expires = NULL, otp_attempts = 0 WHERE id = ?');
                $updateUser->bind_param('si', $hashedPassword, $targetUser['id']);
                $updateUser->execute();
                $updateUser->close();

                $_SESSION['flash_success'] = 'Your password has been reset successfully! Please sign in with your new password.';
                header('Location: login.php');
                exit;
            }
        }
    }
}

$pageTitle = 'Reset Password — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>Reset Your Password</h2>
    <p class="card-sub">Enter the 6-digit OTP code sent to your Gmail and set a new password.</p>

    <?php if ($info !== ''): ?>
        <div class="alert alert-success"><?php echo e($info); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form id="reset-form" method="post" action="reset_password.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address -->
        <div class="form-group">
            <label for="email">Gmail / Email Address</label>
            <input class="form-control" type="email" id="email" name="email"
                   value="<?php echo e($email); ?>" required placeholder="you@gmail.com"
                   <?php echo ($email !== '') ? 'readonly style="background: #f1f5f9; color: #64748b; cursor: not-allowed;"' : ''; ?>>
        </div>

        <!-- 6-Digit Reset OTP -->
        <div class="form-group">
            <label for="otp">6-Digit Reset OTP Code</label>
            <input class="form-control" type="text" id="otp" name="otp"
                   pattern="[0-9]{6}" maxlength="6" required
                   style="font-size: 1.4rem; letter-spacing: 5px; text-align: center; font-weight: bold;"
                   placeholder="------">
        </div>

        <!-- Password (8 to 12 Chars) -->
        <div class="form-group">
            <label for="password">New Password <span style="font-weight:normal; color:var(--text-muted);">(8-12 chars: A-Z, a-z, 0-9, special char)</span></label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password"
                       name="password"
                       required minlength="8" maxlength="12">
                <button type="button" class="toggle-password"
                        data-target="password" aria-label="Show or hide password">&#128065;</button>
            </div>
        </div>

        <!-- Confirm Password -->
        <div class="form-group">
            <label for="confirm_password">Confirm New Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="confirm_password"
                       name="confirm_password"
                       required minlength="8" maxlength="12">
                <button type="button" class="toggle-password"
                        data-target="confirm_password" aria-label="Show or hide password">&#128065;</button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary">Update Password &rarr;</button>
        <p class="form-footer">
            <a href="login.php">&larr; Back to Sign In</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
