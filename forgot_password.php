<?php
/**
 * ============================================================================
 *  forgot_password.php — REQUEST PASSWORD RESET OTP
 * ============================================================================
 *  Accepts user's email address and sends a 6-digit password reset OTP via Gmail SMTP.
 *  Uses generic response to prevent account enumeration attacks.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Already logged in? Redirect to dashboard.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$loginEmail = strtolower(trim($_GET['login_email'] ?? $_POST['login_email'] ?? ''));
if ($loginEmail !== '' && !str_contains($loginEmail, '@')) {
    $loginEmail .= '@gmail.com';
}

$email = $loginEmail !== '' ? $loginEmail : strtolower(trim($_GET['email'] ?? ''));
$info  = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $rawEmail = strtolower(trim($_POST['email'] ?? ''));
        if ($rawEmail !== '' && !str_contains($rawEmail, '@')) {
            $email = $rawEmail . '@gmail.com';
        } else {
            $email = $rawEmail;
        }

        $submittedLoginEmail = strtolower(trim($_POST['login_email'] ?? ''));
        if ($submittedLoginEmail !== '' && !str_contains($submittedLoginEmail, '@')) {
            $submittedLoginEmail .= '@gmail.com';
        }

        $gmailErr = '';

        // Reject if login email was provided and user changed it to a different email
        if ($submittedLoginEmail !== '' && $email !== $submittedLoginEmail) {
            $error = 'Invalid credentials.';
        } elseif (!is_proper_gmail($email, $gmailErr)) {
            $error = 'Invalid credentials.';
        } else {
            // Trigger 6-digit password reset OTP generation & Gmail SMTP dispatch
            $res = send_password_reset_otp($email);
            
            if (!$res['success']) {
                $error = $res['message'];
            } else {
                // Redirect to reset_password.php with email prefilled
                header('Location: reset_password.php?email=' . urlencode($email) . '&sent=1');
                exit;
            }
        }
    }
}

$pageTitle = 'Forgot Password — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>Forgot Password?</h2>
    <p class="card-sub">Enter your account email address to receive a 6-digit password reset OTP code.</p>

    <?php if ($info !== ''): ?>
        <div class="alert alert-success"><?php echo e($info); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form id="forgot-form" method="post" action="forgot_password.php<?php echo $loginEmail !== '' ? '?login_email=' . urlencode($loginEmail) : ''; ?>" autocomplete="off">
        <?php echo csrf_field(); ?>
        <?php if ($loginEmail !== ''): ?>
            <input type="hidden" name="login_email" value="<?php echo e($loginEmail); ?>">
        <?php endif; ?>

        <div class="form-group">
            <label for="email">Gmail / Email Address</label>
            <input class="form-control" type="email" id="email" name="email"
                   value="<?php echo e($email); ?>" required placeholder="you@gmail.com"
                   <?php echo ($email !== '') ? 'readonly style="background: #f1f5f9; color: #64748b; cursor: not-allowed;"' : ''; ?>>
        </div>

        <button type="submit" class="btn btn-primary">Send Reset OTP &rarr;</button>

        <p class="form-footer">
            Remembered your password? <a href="login.php">Sign In here</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
