<?php
/**
 * ============================================================================
 *  mfa_enroll.php — MULTI-FACTOR AUTHENTICATION (MFA/TOTP) ENROLLMENT
 * ============================================================================
 *  Provides secure enrollment for authenticator apps (Google Authenticator, etc.).
 *  Requires Step-Up password verification before enrollment or disabling.
 *  Requires verification of a 6-digit TOTP code before enabling MFA.
 *  Stores encrypted secret and hashed single-use recovery codes in MySQL.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/totp.php';

require_login();
require_step_up(); // Enforce Step-Up Password Re-verification

$userId     = (int)$_SESSION['user_id'];
$userEmail  = $_SESSION['email'] ?? '';
$error      = '';
$successMsg = '';
$recoveryCodes = [];

// Fetch current user MFA state
$stmt = $conn->prepare('SELECT mfa_enabled, mfa_secret_encrypted, mfa_recovery_codes_hash FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $userId);
$stmt->execute();
$userMfa = $stmt->get_result()->fetch_assoc();
$stmt->close();

$mfaEnabled = (int)($userMfa['mfa_enabled'] ?? 0) === 1;

// Handle Disable MFA POST request
if (isset($_POST['action']) && $_POST['action'] === 'disable_mfa') {
    if (is_admin()) {
        $error = 'MFA Protection: Multi-Factor Authentication is mandatory for Administrator accounts and cannot be disabled.';
    } else {
        $submittedToken = $_POST['csrf_token'] ?? '';
        if (!verify_csrf($submittedToken)) {
            $error = 'Invalid security token or session expired.';
        } else {
            $upd = $conn->prepare('UPDATE users SET mfa_enabled = 0, mfa_secret_encrypted = NULL, mfa_recovery_codes_hash = NULL WHERE id = ?');
            $upd->bind_param('i', $userId);
            $upd->execute();
            $upd->close();

            log_security_event('MFA_DISABLED', ['user_id' => $userId], $userId, 'WARNING');
            $mfaEnabled = false;
            $successMsg = 'Multi-Factor Authentication has been disabled for your account.';
        }
    }
}

// Generate temporary secret if enrollment pending
if (!$mfaEnabled) {
    if (empty($_SESSION['mfa_setup_secret'])) {
        $_SESSION['mfa_setup_secret'] = TOTP::generateSecret();
    }
    $setupSecret = $_SESSION['mfa_setup_secret'];
    $otpAuthUrl  = TOTP::getOtpAuthUrl($userEmail, 'SecureAuth', $setupSecret);
    $qrUrl       = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpAuthUrl);
}

// Handle Verify & Enable MFA POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'enable_mfa') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $inputCode   = trim($_POST['totp_code'] ?? '');
        $setupSecret = $_SESSION['mfa_setup_secret'] ?? '';

        if (empty($setupSecret)) {
            $error = 'MFA session expired. Please refresh the page and try again.';
        } elseif (!TOTP::verifyCode($setupSecret, $inputCode)) {
            log_security_event('MFA_ENROLLMENT_FAILED', ['user_id' => $userId, 'reason' => 'invalid_code'], $userId, 'WARNING');
            $error = 'Invalid 6-digit authenticator code. Please check your app and try again.';
        } else {
            // Generate 8 single-use recovery codes
            $rawRecoveryCodes = TOTP::generateRecoveryCodes(8);
            $hashedCodes = array_map(function ($code) {
                return password_hash(str_replace('-', '', $code), PASSWORD_DEFAULT);
            }, $rawRecoveryCodes);

            $encryptedSecret = encrypt_pii($setupSecret);
            $jsonHashedCodes = json_encode($hashedCodes);

            $upd = $conn->prepare('UPDATE users SET mfa_enabled = 1, mfa_secret_encrypted = ?, mfa_recovery_codes_hash = ? WHERE id = ?');
            $upd->bind_param('ssi', $encryptedSecret, $jsonHashedCodes, $userId);
            $upd->execute();
            $upd->close();

            log_security_event('MFA_ENROLLED_SUCCESSFULLY', ['user_id' => $userId], $userId, 'INFO');

            unset($_SESSION['mfa_setup_secret']);
            $mfaEnabled = true;
            $recoveryCodes = $rawRecoveryCodes;
            $successMsg = 'Multi-Factor Authentication enabled successfully!';
        }
    }
}

$pageTitle = 'MFA Enrollment — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
        <div>
            <h2>🔐 Multi-Factor Authentication (MFA / 2FA)</h2>
            <p class="card-sub" style="margin-bottom: 0;">Protect your account with an Authenticator App (Google Authenticator, Authy, etc.).</p>
        </div>
        <div>
            <a href="profile.php" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;">&larr; Back to Profile</a>
        </div>
    </div>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <?php if ($mfaEnabled && !empty($recoveryCodes)): ?>
        <!-- Display Recovery Codes Once After Enabling -->
        <div style="background: #fffbeb; border: 1.5px solid #fde68a; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem;">
            <h3 style="color: #92400e; margin-bottom: 0.5rem;">⚠️ Save Your Emergency Recovery Codes</h3>
            <p style="font-size: 0.9rem; color: #78350f; margin-bottom: 1rem;">
                If you lose access to your authenticator device, you can use one of these single-use recovery codes to sign in. Store them in a safe place.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; background: #ffffff; padding: 1rem; border-radius: 6px; border: 1px solid #fcd34d;">
                <?php foreach ($recoveryCodes as $code): ?>
                    <code style="font-size: 1.1rem; font-weight: 700; color: #1e293b; letter-spacing: 1px;"><?php echo e($code); ?></code>
                <?php endforeach; ?>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($mfaEnabled): ?>
        <!-- Active MFA Status Panel -->
        <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; margin-bottom: 2rem;">
            <div style="font-size: 3rem; margin-bottom: 0.5rem;">🛡️</div>
            <h3 style="color: var(--success); margin-bottom: 0.5rem;">MFA is Active on Your Account</h3>
            <p style="color: var(--text-muted); font-size: 0.9rem; max-width: 500px; margin: 0 auto 1.5rem;">
                Your account is secured with 2FA authenticator app verification. Every sign-in requires a 6-digit TOTP code from your mobile device.
            </p>

            <?php if (is_admin()): ?>
                <div class="alert alert-info" style="max-width: 500px; margin: 0 auto; font-size: 0.85rem;">
                    ℹ️ MFA is mandatory for Administrator accounts and cannot be disabled.
                </div>
            <?php else: ?>
                <form method="post" action="mfa_enroll.php" style="margin: 0;">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="action" value="disable_mfa">
                    <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to disable Multi-Factor Authentication?');">
                        Disable MFA &rarr;
                    </button>
                </form>
            <?php endif; ?>
        </div>
    <?php else: ?>
        <!-- Enrollment Form -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem; margin-bottom: 2rem;">
            <!-- Step 1: Scan QR Code -->
            <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center;">
                <h3 style="margin-bottom: 0.5rem; color: var(--primary);">Step 1: Scan QR Code</h3>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
                    Open Google Authenticator, Authy, or 1Password on your phone and scan the QR code below:
                </p>
                <div style="background: #ffffff; padding: 1rem; border-radius: 8px; display: inline-block; border: 1px solid var(--border); margin-bottom: 1rem;">
                    <img src="<?php echo e($qrUrl); ?>" alt="MFA QR Code" width="180" height="180">
                </div>
                <div style="font-size: 0.8rem; color: var(--text-muted);">
                    Or enter key manually: <strong style="font-family: monospace; letter-spacing: 1px; color: var(--text-dark);"><?php echo e($setupSecret); ?></strong>
                </div>
            </div>

            <!-- Step 2: Verify & Enable -->
            <div style="background: var(--bg-light); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem;">
                <h3 style="margin-bottom: 0.5rem; color: var(--primary);">Step 2: Enter 6-Digit Code</h3>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.5rem;">
                    Enter the 6-digit code generated by your authenticator app to confirm setup and activate MFA:
                </p>

                <form method="post" action="mfa_enroll.php" autocomplete="off">
                    <?php echo csrf_field(); ?>
                    <input type="hidden" name="action" value="enable_mfa">

                    <div class="form-group">
                        <label for="totp_code">6-Digit Authenticator Code</label>
                        <input class="form-control" type="text" id="totp_code" name="totp_code"
                               pattern="[0-9]{6}" maxlength="6" required autofocus
                               inputmode="numeric"
                               autocomplete="one-time-code"
                               style="font-size: 1.5rem; letter-spacing: 6px; text-align: center; font-weight: 700;">
                    </div>

                    <button type="submit" class="btn btn-primary" style="width: 100%;">Verify &amp; Enable MFA &rarr;</button>
                </form>
            </div>
        </div>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
