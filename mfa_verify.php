<?php
/**
 * ============================================================================
 *  mfa_verify.php — MULTI-FACTOR AUTHENTICATION LOGIN VERIFICATION
 * ============================================================================
 *  Intercepts login flow for MFA-enabled accounts and Administrators.
 *  Verifies 6-digit TOTP authenticator code or single-use recovery code.
 *  Grants full session upon successful verification.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/totp.php';

// Must have an active MFA pending login state
if (empty($_SESSION['mfa_pending'])) {
    header('Location: login.php');
    exit;
}

$pending = $_SESSION['mfa_pending'];
$userId  = (int)$pending['user_id'];
$error   = '';

// Fetch user's encrypted MFA secret and recovery codes
$stmt = $conn->prepare('SELECT fullname, email, role, mfa_enabled, mfa_secret_encrypted, mfa_recovery_codes_hash FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $userId);
$stmt->execute();
$userMfa = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$userMfa) {
    unset($_SESSION['mfa_pending']);
    header('Location: login.php');
    exit;
}

$decryptedSecret = !empty($userMfa['mfa_secret_encrypted']) ? decrypt_pii($userMfa['mfa_secret_encrypted']) : '';
$isAdminAccount  = strtolower($userMfa['role']) === 'admin';

// Handle TOTP / Recovery Code Verification
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $rateCheck = check_rate_limit($conn, $ipAddress, 'mfa_verify', 5, 300);

        if (!$rateCheck['allowed']) {
            $error = 'Too many failed 2FA attempts. Account/IP temporarily restricted.';
        } else {
            $code = trim($_POST['mfa_code'] ?? '');
            $codeClean = str_replace('-', '', $code);

            $verified = false;

            // 1. Verify TOTP Code
            if ($decryptedSecret !== '' && TOTP::verifyCode($decryptedSecret, $codeClean)) {
                $verified = true;
            }

            // 2. Fallback: Verify Recovery Code
            if (!$verified && !empty($userMfa['mfa_recovery_codes_hash'])) {
                $hashedCodes = json_decode($userMfa['mfa_recovery_codes_hash'], true) ?: [];
                foreach ($hashedCodes as $idx => $hashedCode) {
                    if (password_verify($codeClean, $hashedCode)) {
                        $verified = true;
                        // Single-use: remove used recovery code
                        unset($hashedCodes[$idx]);
                        $newHashedCodes = json_encode(array_values($hashedCodes));
                        $upd = $conn->prepare('UPDATE users SET mfa_recovery_codes_hash = ? WHERE id = ?');
                        $upd->bind_param('si', $newHashedCodes, $userId);
                        $upd->execute();
                        $upd->close();

                        log_security_event('MFA_RECOVERY_CODE_USED', ['user_id' => $userId], $userId, 'WARNING');
                        break;
                    }
                }
            }

            if ($verified) {
                // Grant full session authentication
                regenerate_session();
                $_SESSION['user_id']           = $userMfa['id'];
                $_SESSION['fullname']          = $userMfa['fullname'];
                $_SESSION['email']             = $userMfa['email'];
                $_SESSION['role']              = $userMfa['role'];
                $_SESSION['mfa_authenticated'] = true;
                $_SESSION['last_password_verified_at'] = time();

                unset($_SESSION['mfa_pending']);
                reset_rate_limit($conn, $ipAddress, 'mfa_verify');

                log_security_event('MFA_LOGIN_SUCCESS', ['user_id' => $userId, 'role' => $userMfa['role']], $userId, 'INFO');

                if ($isAdminAccount) {
                    header('Location: admin/index.php');
                } else {
                    header('Location: dashboard.php');
                }
                exit;
            } else {
                record_rate_limit_attempt($conn, $ipAddress, 'mfa_verify', 5, 300);
                log_security_event('MFA_LOGIN_FAILED', ['user_id' => $userId], $userId, 'WARNING');
                $error = 'Invalid authenticator code or recovery code. Please check and try again.';
            }
        }
    }
}

$pageTitle = '2FA Verification — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="max-width: 480px; margin: 3rem auto;">
    <div style="text-align: center; margin-bottom: 1.5rem;">
        <div style="font-size: 3rem; margin-bottom: 0.5rem;">🔐</div>
        <h2>Two-Factor Verification</h2>
        <p class="card-sub">
            Enter the 6-digit code from your authenticator app to complete sign-in for <strong><?php echo e($pending['email']); ?></strong>.
        </p>
    </div>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <form method="post" action="mfa_verify.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <div class="form-group">
            <label for="mfa_code">6-Digit Code or Recovery Code</label>
            <input class="form-control" type="text" id="mfa_code" name="mfa_code"
                   required autofocus maxlength="12"
                   inputmode="numeric"
                   autocomplete="one-time-code"
                   style="font-size: 1.4rem; letter-spacing: 4px; text-align: center; font-weight: 700;">
            <small style="color: var(--text-muted); font-size: 0.8rem; display: block; margin-top: 0.35rem; text-align: center;">
                Accepts 6-digit authenticator codes or emergency recovery codes.
            </small>
        </div>

        <button type="submit" class="btn btn-primary" style="width: 100%;">Verify &amp; Sign In &rarr;</button>

        <div style="margin-top: 1rem; text-align: center;">
            <a href="login.php" style="color: var(--text-muted); font-size: 0.88rem; text-decoration: none;">&larr; Return to Sign In</a>
        </div>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
