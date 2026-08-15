<?php
/**
 * ============================================================================
 *  step_up.php — STEP-UP AUTHENTICATION (PASSWORD + GMAIL OTP VERIFICATION)
 * ============================================================================
 *  Requires authentication. Enforces password re-verification AND a 6-digit
 *  Gmail verification OTP before allowing sensitive security operations.
 *  Sets a 5-minute (300 seconds) elevated-authentication state window.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_login();

$userId     = (int)$_SESSION['user_id'];
$userEmail  = $_SESSION['email'] ?? '';
$fullname   = $_SESSION['fullname'] ?? 'User';

$returnTo   = $_GET['return_to'] ?? $_POST['return_to'] ?? 'dashboard.php';
if (!preg_match('/^[a-z0-9_\-\.\/]+\.php(\?[a-z0-9_&=\-\.\%]*)?$/i', $returnTo) || str_contains($returnTo, '://')) {
    $returnTo = 'dashboard.php';
}

$error      = '';
$success    = '';

// Check OTP Cooldown & Remaining Expiry
$cooldown = can_resend_otp($userId);
if ($cooldown > 60) { $cooldown = 60; }
$otpRemaining = max(0, (int)($_SESSION['otp_pending']['expires'] ?? 0) - time());

// Auto-send OTP on first arrival if none active
if (empty($_SESSION['otp_pending']) || time() > ($_SESSION['otp_pending']['expires'] ?? 0)) {
    $otpSendRes = send_verification_otp($userId, $userEmail, $fullname);
    if ($otpSendRes['success']) {
        $cooldown = 60;
        $otpRemaining = 60;
    }
}

// Handle Resend Gmail OTP Request
if (isset($_POST['action']) && $_POST['action'] === 'resend_otp') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $otpRes = send_verification_otp($userId, $userEmail, $fullname);
        if ($otpRes['success']) {
            $success = 'A new 6-digit OTP code has been sent to your Gmail address!';
            $cooldown = 60;
            $otpRemaining = 60;
        } else {
            $error    = $otpRes['message'];
            $cooldown = $otpRes['cooldown'] ?? $cooldown;
        }
    }
}

// Handle Form Submission (Password + Gmail OTP Verification)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($_POST['action']) || $_POST['action'] === 'verify_step_up')) {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $password = $_POST['password'] ?? '';
        $otpInput = trim($_POST['otp_code'] ?? '');

        // 1. Verify Password
        $stmt = $conn->prepare('SELECT password FROM users WHERE id = ? LIMIT 1');
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $passwordValid = ($user && password_verify($password, $user['password']));

        // 2. Verify Gmail OTP
        $otpRes = verify_email_otp($userId, $otpInput);
        $otpValid = $otpRes['success'];

        if (!$passwordValid) {
            log_security_event('STEP_UP_AUTHENTICATION_FAILED', ['user_id' => $userId, 'reason' => 'invalid_password'], $userId, 'WARNING');
            $error = 'Current account password is incorrect.';
        } elseif (!$otpValid) {
            log_security_event('STEP_UP_AUTHENTICATION_FAILED', ['user_id' => $userId, 'reason' => 'invalid_otp'], $userId, 'WARNING');
            $error = $otpRes['message'] ?? 'Invalid or expired 6-digit Gmail verification code.';
        } else {
            // Elevated authentication granted for 300 seconds (5 minutes)
            $_SESSION['last_password_verified_at'] = time();

            // Update timestamp in database
            $upd = $conn->prepare('UPDATE users SET last_password_verified_at = NOW() WHERE id = ?');
            $upd->bind_param('i', $userId);
            $upd->execute();
            $upd->close();

            log_security_event('STEP_UP_AUTHENTICATION_SUCCESS', ['user_id' => $userId, 'return_to' => $returnTo], $userId, 'INFO');

            header('Location: ' . $returnTo);
            exit;
        }
    }
}

$pageTitle = 'Security Re-Verification — Password & Gmail OTP';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="max-width: 520px; margin: 2.5rem auto;">
    <div style="text-align: center; margin-bottom: 1.5rem;">
        <div style="font-size: 3rem; margin-bottom: 0.5rem;">🔒</div>
        <h2>Security Re-Verification Required</h2>
        <p class="card-sub">
            Please enter your account password and the 6-digit verification code sent to your Gmail (<strong><?php echo e($userEmail); ?></strong>).
        </p>
    </div>

    <!-- OTP Sent Confirmation Alert Banner -->
    <div class="alert alert-success">
        ✅ A 6-digit OTP verification code has been sent to your Gmail (<strong><?php echo e($userEmail); ?></strong>).
    </div>

    <?php if ($success !== ''): ?>
        <div class="alert alert-success"><?php echo e($success); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form id="stepup-form" method="post" action="step_up.php" autocomplete="off">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="return_to" value="<?php echo e($returnTo); ?>">
        <input type="hidden" name="action" value="verify_step_up">

        <!-- 1. Password Verification -->
        <div class="form-group">
            <label for="password">Current Account Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password" name="password" required autofocus autocomplete="current-password">
                <button type="button" class="toggle-password" data-target="password" aria-label="Show or hide password">👁️</button>
            </div>
        </div>

        <!-- 2. Gmail 6-Digit Verification OTP -->
        <div class="form-group">
    <label for="otp_code">6-Digit Gmail Verification OTP</label>

    <input
        class="form-control"
        type="text"
        id="otp_code"
        name="otp_code"
        pattern="[0-9]{6}"
        maxlength="6"
        required
        inputmode="numeric"
        autocomplete="off"
        spellcheck="false"
        style="font-size: 1.4rem; letter-spacing: 6px; text-align: center; font-weight: 700;"
    >

    <small
        id="otp-timer"
        data-remaining="<?php echo (int)$otpRemaining; ?>"
        style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 0.35rem; text-align: center;"
    >
        Code expires in
        <strong id="otp-count"><?php echo (int)$otpRemaining; ?></strong>
        second(s).
    </small>
</div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Confirm Identity &amp; Proceed &rarr;</button>
    </form>

    <!-- Interactive Resend OTP Button with Live Cooldown Timer -->
    <div style="margin-top: 1.5rem; text-align: center; border-top: 1px solid var(--border); padding-top: 1.25rem;">
        <form id="resend-otp-form" method="post" action="step_up.php" style="margin: 0; display: inline-block;">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="return_to" value="<?php echo e($returnTo); ?>">
            <input type="hidden" name="action" value="resend_otp">
            <button type="submit" id="resend-btn" class="btn"
                    data-cooldown="<?php echo (int)$cooldown; ?>"
                    <?php echo ($cooldown > 0) ? 'disabled' : ''; ?>
                    style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); font-size: 0.88rem;">
                🔄 <span id="resend-text">Resend Code</span>
            </button>
        </form>
        <div style="margin-top: 0.75rem;">
            <a href="dashboard.php" style="color: var(--text-muted); font-size: 0.88rem; text-decoration: none;">&larr; Cancel &amp; Return to Dashboard</a>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
