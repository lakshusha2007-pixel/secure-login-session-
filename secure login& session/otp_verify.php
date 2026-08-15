<?php
/**
 * ============================================================================
 *  otp_verify.php — 2FA OTP CODE VERIFICATION PAGE
 * ============================================================================
 *  2FA Verification page with Localhost Test Mode banner displaying the generated
 *  OTP code and 1-click auto-fill for seamless local testing.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Already logged in? No need for OTP.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

// No OTP pending or expired? Send back to login.php.
if (!is_otp_pending()) {
    header('Location: login.php');
    exit;
}

$error = '';
$pending = $_SESSION['otp_pending'];

// Handle Resend OTP Request
if (isset($_GET['resend'])) {
    $newOtp = generate_otp([
        'id'       => $pending['user_id'],
        'fullname' => $pending['fullname'],
        'email'    => $pending['email'],
        'phone'    => $pending['phone'],
        'role'     => $pending['role'],
    ]);
    header('Location: otp_verify.php?resent=1');
    exit;
}

// Handle OTP Verification Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    $inputOtp       = trim($_POST['otp'] ?? '');

    if (!verify_csrf($submittedToken)) {
        $error = 'Expired or invalid security token. Please try again.';
    } elseif ($inputOtp === '') {
        $error = 'Please enter the 6-digit OTP code.';
    } elseif (!verify_otp($inputOtp)) {
        $error = 'Invalid OTP code. Please check the code and try again.';
    } else {
        // SUCCESS: Finalize authentication
        $userData = $_SESSION['otp_pending'];
        unset($_SESSION['otp_pending']);

        // Regenerate session ID (Session Fixation protection)
        regenerate_session();

        // Populate session identity
        $_SESSION['user_id']  = $userData['user_id'];
        $_SESSION['fullname'] = $userData['fullname'];
        $_SESSION['email']    = $userData['email'];
        $_SESSION['phone']    = $userData['phone'];
        $_SESSION['role']     = $userData['role'];

        header('Location: dashboard.php');
        exit;
    }
}

$pageTitle = '2FA OTP Verification — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>&#128274; Two-Factor Verification</h2>
    <p class="card-sub">
        Verification required for <strong><?php echo e($pending['phone'] ?: $pending['email']); ?></strong>.
    </p>

    <!-- Localhost Test Mode Banner: Displays generated OTP for seamless local testing -->
    <div style="background: #eff6ff; border: 1px dashed #3b82f6; border-radius: 8px; padding: 0.9rem 1rem; margin-bottom: 1.25rem; font-size: 0.9rem; color: #1e40af;">
        <strong>&#128241; Localhost Test Mode (No Paid SMS Gateway Needed):</strong><br>
        OTP generated for <strong><?php echo e($pending['phone'] ?: '+919876543210'); ?></strong> is:
        <span style="font-size: 1.4rem; font-weight: 800; letter-spacing: 3px; color: #1d4ed8; display: inline-block; margin: 0 0.4rem;">
            <?php echo e($pending['otp']); ?>
        </span>
        <button type="button" onclick="document.getElementById('otp').value='<?php echo e($pending['otp']); ?>';" style="background: #2563eb; color: #fff; border: none; border-radius: 4px; padding: 0.25rem 0.65rem; font-size: 0.78rem; cursor: pointer; font-weight: bold; margin-left: 0.5rem;">
            ⚡ Auto-Fill Code
        </button>
    </div>

    <?php if (isset($_GET['registered'])): ?>
        <div class="alert alert-success">&#10004; Account created successfully! Enter the OTP code above or use test code 123456.</div>
    <?php endif; ?>

    <?php if (isset($_GET['resent'])): ?>
        <div class="alert alert-success">&#10004; A new OTP verification code has been generated above!</div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form id="otp-form" method="post" action="otp_verify.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <label for="otp">Enter 6-Digit OTP Code</label>
            <input class="form-control" type="text" id="otp" name="otp"
                   value=""
                   pattern="[0-9]{6}"
                   maxlength="6"
                   style="font-size: 1.4rem; letter-spacing: 4px; text-align: center; font-weight: bold;"
                   required autofocus>
            <small style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 0.3rem;">
                Code is valid for 5 minutes. (Or enter universal test code <code>123456</code>)
            </small>
        </div>

        <button type="submit" class="btn btn-primary">&#10004; Verify OTP &amp; Log In</button>

        <p class="form-footer">
            Didn't get the code? <a href="otp_verify.php?resend=1">Resend OTP</a> | <a href="login.php">Change Account</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
