<?php
/**
 * ============================================================================
 *  otp_verify.php — GMAIL 6-DIGIT HASHED OTP VERIFICATION PAGE
 * ============================================================================
 *  Verifies 6-digit OTP code against password_hash() stored in MySQL.
 *  Includes 60-second resend cooldown timer, 60-second OTP expiry, and rate-limiting.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Already logged in? Redirect to dashboard.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

// No OTP pending session? Redirect to login.php.
if (empty($_SESSION['otp_pending']['user_id'])) {
    header('Location: login.php');
    exit;
}

$pending  = $_SESSION['otp_pending'];
$userId   = (int) $pending['user_id'];
$email    = $pending['email'];
$fullname = $pending['fullname'];

$error      = '';
$successMsg = '';
$cooldown   = can_resend_otp($userId);
if ($cooldown > 60) { $cooldown = 60; }

$otpRemaining = max(0, (int)($pending['expires'] ?? 0) - time());

// Handle Resend OTP Request
if (isset($_POST['action']) && $_POST['action'] === 'resend_otp') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Expired security token. Please try again.';
    } else {
        $resendResult = send_verification_otp($userId, $email, $fullname);
        if ($resendResult['success']) {
            $successMsg = 'A new 6-digit OTP code has been sent to your Gmail address!';
            $cooldown   = 60;
            $otpRemaining = 60;
        } else {
            $error    = $resendResult['message'];
            $cooldown = $resendResult['cooldown'] ?? $cooldown;
        }
    }
}

// Handle OTP Verification Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (!isset($_POST['action']) || $_POST['action'] === 'verify_otp')) {
    $submittedToken = $_POST['csrf_token'] ?? '';
    $inputOtp       = trim($_POST['otp'] ?? '');

    if (!verify_csrf($submittedToken)) {
        $error = 'Expired or invalid security token. Please try again.';
    } elseif ($inputOtp === '') {
        $error = 'Please enter the 6-digit OTP code.';
    } else {
        $verifyRes = verify_email_otp($userId, $inputOtp);

        if (!$verifyRes['success']) {
            log_security_event('OTP_VERIFY_FAILED', ['user_id' => $userId, 'email' => $email, 'reason' => $verifyRes['message']], $userId, 'WARNING');
            $error = $verifyRes['message'];
        } else {
            // SUCCESS: Fetch updated user profile
            $stmt = $conn->prepare('SELECT id, fullname, email, role FROM users WHERE id = ? LIMIT 1');
            $stmt->bind_param('i', $userId);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            // Regenerate session ID (Session Fixation protection)
            regenerate_session();

            // Establish authenticated session
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['fullname'] = $user['fullname'];
            $_SESSION['email']    = $user['email'];
            $_SESSION['role']     = $user['role'];

            log_security_event('LOGIN_SUCCESS', ['email' => $user['email'], 'method' => 'OTP_2FA'], (int)$user['id'], 'INFO');

            header('Location: dashboard.php');
            exit;
        }
    }
}

$pageTitle = 'Gmail OTP Verification — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>Gmail OTP Verification</h2>
    <p class="card-sub">
        Enter the 6-digit verification code sent to <strong><?php echo e($email); ?></strong>.
    </p>

    <?php if (isset($_GET['registered'])): ?>
        <div class="alert alert-success">Account created! Please enter the 6-digit OTP code.</div>
    <?php endif; ?>

    <?php if (isset($_GET['sent'])): ?>
        <div class="alert alert-success">A 6-digit OTP verification code has been sent to your Gmail inbox.</div>
    <?php endif; ?>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <!-- OTP Verification Form -->
    <form id="otp-form" method="post" action="otp_verify.php" autocomplete="off">
        <?php echo csrf_field(); ?>
        <input type="hidden" name="action" value="verify_otp">

        <div class="form-group">
            <label for="otp">6-Digit Code</label>
            <input class="form-control" type="text" id="otp" name="otp"
                   value=""
                   pattern="[0-9]{6}"
                   maxlength="6"
                   inputmode="numeric"
                   autocomplete="one-time-code"
                   style="font-size: 1.5rem; letter-spacing: 6px; text-align: center; font-weight: 700;"
                   required autofocus>
            <small style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 0.35rem;">
                Check your inbox and spam folder.
            </small>
            <small id="otp-timer" data-remaining="<?php echo (int)$otpRemaining; ?>" style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 0.2rem;">
                Code expires in <strong id="otp-count"><?php echo (int)$otpRemaining; ?></strong> second(s).
            </small>
        </div>

        <button type="submit" class="btn btn-primary" style="width: 100%;">Verify &amp; Continue &rarr;</button>
    </form>

    <!-- Resend OTP Form -->
    <div style="margin-top: 1.5rem; text-align: center; border-top: 1px solid var(--border); padding-top: 1.25rem;">
        <form id="resend-otp-form" method="post" action="otp_verify.php" style="margin: 0; display: inline-block;">
            <?php echo csrf_field(); ?>
            <input type="hidden" name="action" value="resend_otp">
            <button type="submit" id="resend-btn" class="btn"
                    data-cooldown="<?php echo (int)$cooldown; ?>"
                    <?php echo ($cooldown > 0) ? 'disabled' : ''; ?>
                    style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); font-size: 0.88rem;">
                🔄 <span id="resend-text">Resend Code</span>
            </button>
        </form>
        <p class="form-footer" style="margin-top: 0.75rem;">
            <a href="login.php">&larr; Back to Sign In</a>
        </p>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

