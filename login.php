<?php
/**
 * ============================================================================
 *  login.php — SECURE SIGN-IN PAGE (DIRECT AUTHENTICATION & GOOGLE OAUTH)
 * ============================================================================
 *  Fields:
 *      1. Gmail Address / Username
 *      2. Password
 *
 *  Flow:
 *      - Server-side lookup by Username (Full Name) OR Email address.
 *      - Prepared SQL Query (`SELECT id, fullname, email, phone, password, role, email_verified FROM users ...`).
 *      - `password_verify()` check.
 *      - 6-digit OTP emailed to the registered Gmail address (required before access).
 *      - Google OAuth 2.0 Integration button ("Continue with Google").
 *      - "Forgot Password?" recovery link.
 * ============================================================================
 */

// Load auth helpers: secure session config + DB connection + functions.
require_once __DIR__ . '/includes/auth.php';

// Already logged in? Go straight to dashboard.
if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

// --- Local variables used by the HTML form ----------------------------------
$identity   = '';
$error      = '';
$successMsg = '';
$lockTime   = 0;

if (!empty($_SESSION['flash_success'])) {
    $successMsg = $_SESSION['flash_success'];
    unset($_SESSION['flash_success']);
}

if (!empty($_SESSION['flash_error'])) {
    $error = $_SESSION['flash_error'];
    unset($_SESSION['flash_error']);
}

if ($successMsg === '' && isset($_GET['logged_out'])) {
    $successMsg = 'You have been logged out successfully.';
}

// --- Handle the form submission ---------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        log_security_event('CSRF_TOKEN_MISMATCH', ['action' => 'login'], null, 'WARNING');
        $error = 'Invalid credentials.';
    } else {
        $identity = trim($_POST['identity'] ?? '');
        $password = $_POST['password'] ?? '';

        // Formulate potential email address (append @gmail.com if prefix provided)
        $cleanIdentity = preg_replace('/@gmail\.com$/i', '', $identity);
        $possibleEmail = strtolower($cleanIdentity . '@gmail.com');
        $rawIdentity   = strtolower($identity);

        if ($identity === '' || $password === '') {
            log_security_event('LOGIN_FAILED', ['identity' => $identity, 'reason' => 'empty_fields'], null, 'WARNING');
            $error = 'Invalid credentials.';
        } elseif (function_exists('detect_sqli_pattern') && (detect_sqli_pattern($identity) || detect_sqli_pattern($password))) {
            $att1  = record_failed_attempt($possibleEmail);
            $att2  = record_failed_attempt($rawIdentity);
            $currentAttempts = max($att1, $att2);
            log_security_event('SQLI_PROBE_BLOCKED', ['identity' => $identity], null, 'ALERT');
            
            if ($currentAttempts >= MAX_ATTEMPTS) {
                $error = 'Too many login attempts (Attempt 3 to 3). Account is inactive for 24 hours.';
            } elseif ($currentAttempts === 2) {
                $error = 'Invalid credentials (Attempt 2 to 3). You have 1 attempt remaining.';
            } else {
                $error = 'Invalid credentials (Attempt 1 to 3). You have 2 attempts remaining.';
            }
        } else {
            $dbLock = is_db_account_locked($conn, $identity);
            $sessLock1 = is_login_locked($possibleEmail);
            $sessLock2 = is_login_locked($rawIdentity);

            if ($dbLock['is_locked'] || $sessLock1 || $sessLock2) {
                $lockTime = max($dbLock['remaining'], get_lock_remaining($possibleEmail), get_lock_remaining($rawIdentity));
                log_security_event('LOCKOUT_BLOCKED_ATTEMPT', ['identity' => $identity, 'remaining_sec' => $lockTime], null, 'WARNING');
                $error    = 'Too many login attempts. Account is inactive for 24 hours.';
            } else {
                // Prepared Statement: lookup user by Email OR Username (Parameterized SQL Query)
                $stmt = $conn->prepare('SELECT id, fullname, email, phone, password, role, email_verified, is_active FROM users WHERE LOWER(email) = ? OR LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1');
                $stmt->bind_param('sss', $rawIdentity, $possibleEmail, $cleanIdentity);
                $stmt->execute();
                $result = $stmt->get_result();
                $user   = $result->fetch_assoc();
                $stmt->close();

                $passwordOk = $user !== null && password_verify($password, $user['password']);

                if ($user !== null && (int)($user['is_active'] ?? 1) === 0) {
                    log_security_event('INACTIVE_ACCOUNT_LOGIN_ATTEMPT', ['identity' => $identity, 'user_id' => $user['id']], (int)$user['id'], 'WARNING');
                    $error = 'Your account is currently inactive. Please try again after 24 hours.';
                } elseif ($passwordOk) {
                    // Session Fixation Defence: Regenerate session ID immediately after valid credentials
                    regenerate_session();

                    // Transparently upgrade legacy bcrypt hash to Argon2id if supported
                    check_and_upgrade_password($conn, (int)$user['id'], $password, $user['password']);

                    reset_failed_attempts($possibleEmail);
                    reset_failed_attempts($rawIdentity);
                    reset_db_failed_attempts($conn, (int)$user['id']);

                    log_security_event('LOGIN_PASSWORD_VERIFIED', ['identity' => $identity, 'email' => $user['email']], (int)$user['id'], 'INFO');

                    // Check if MFA enabled or Admin (Mandatory MFA for Admins)
                    $isMfaActive = (int)($user['mfa_enabled'] ?? 0) === 1;
                    $isAdminRole = strtolower($user['role'] ?? '') === 'admin';

                    if ($isMfaActive) {
                        $_SESSION['mfa_pending'] = [
                            'user_id'  => (int)$user['id'],
                            'fullname' => $user['fullname'],
                            'email'    => $user['email'],
                            'role'     => $user['role']
                        ];
                        header('Location: mfa_verify.php');
                        exit;
                    } elseif ($isAdminRole) {
                        // Admin mandatory MFA enrollment
                        $_SESSION['user_id']  = (int)$user['id'];
                        $_SESSION['fullname'] = $user['fullname'];
                        $_SESSION['email']    = $user['email'];
                        $_SESSION['role']     = $user['role'];
                        $_SESSION['last_password_verified_at'] = time();

                        log_security_event('MFA_MANDATORY_ADMIN_REDIRECT', ['user_id' => (int)$user['id']], (int)$user['id'], 'WARNING');
                        header('Location: mfa_enroll.php?mandatory_admin=1');
                        exit;
                    } else {
                        // Generate fresh 6-digit Gmail Verification OTP code & send via SMTP
                        send_verification_otp((int)$user['id'], $user['email'], $user['fullname']);

                        // Redirect user to Gmail OTP verification page
                        header('Location: otp_verify.php?sent=1');
                        exit;
                    }
                } else {
                    $att1  = record_failed_attempt($possibleEmail);
                    $att2  = record_failed_attempt($rawIdentity);
                    $dbAtt = record_db_failed_attempt($conn, $identity);

                    $currentAttempts = max($att1, $att2, $dbAtt);

                    log_security_event('LOGIN_FAILED', ['identity' => $identity, 'attempt_count' => $currentAttempts], $user ? (int)$user['id'] : null, 'WARNING');

                    if ($currentAttempts >= MAX_ATTEMPTS) {
                        $dbLock   = is_db_account_locked($conn, $identity);
                        $lockTime = max($dbLock['remaining'], get_lock_remaining($possibleEmail), get_lock_remaining($rawIdentity), LOCK_SECONDS);
                        log_security_event('LOCKOUT_TRIGGERED', ['identity' => $identity, 'lockout_seconds' => $lockTime], $user ? (int)$user['id'] : null, 'ALERT');
                        $error    = 'Too many login attempts (Attempt 3 to 3). Account is inactive for 24 hours.';
                    } elseif ($currentAttempts === 2) {
                        $error    = 'Invalid credentials (Attempt 2 to 3). You have 1 attempt remaining.';
                    } else {
                        $error    = 'Invalid credentials (Attempt 1 to 3). You have 2 attempts remaining.';
                    }
                }
            }
        }
    }
}

// Generate OAuth URL with CSRF state token
if (GOOGLE_CLIENT_ID === 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com') {
    $googleAuthUrl = 'oauth_callback.php?code=demo_oauth_code&state=' . urlencode(csrf_token());
} else {
    $googleAuthUrl = get_google_auth_url(csrf_token());
}

// --- Build the page ---------------------------------------------------------
$pageTitle = 'Sign In — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>Sign In to Your Account</h2>
    <p class="card-sub">Enter your Gmail address and password to continue.</p>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error">
            <?php
            echo e($error);
            if ($lockTime > 0) {
                $hours = (int) floor($lockTime / 3600);
                $mins  = (int) ceil(($lockTime % 3600) / 60);
                if ($hours > 0) {
                    echo ' <strong>Try again in about ' . $hours . ' hour' . ($hours > 1 ? 's' : '') . ($mins > 0 ? ' ' . $mins . ' minute' . ($mins > 1 ? 's' : '') : '') . '.</strong>';
                } else {
                    echo ' <strong>Try again in about ' . $mins . ' minute' . ($mins > 1 ? 's' : '') . '.</strong>';
                }
            }
            ?>
        </div>
    <?php endif; ?>

    <!-- Continue with Google OAuth Button -->
    <div style="margin-bottom: 1.25rem;">
        <a class="btn btn-google" href="<?php echo e($googleAuthUrl); ?>" style="display: flex; align-items: center; justify-content: center; gap: 0.75rem; width: 100%; padding: 0.75rem 1rem; border-radius: var(--radius-sm); border: 1.5px solid var(--border); background: #ffffff; color: var(--text-main); font-weight: 600; text-decoration: none;">
            <svg width="20" height="20" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            Continue with Google
        </a>
    </div>

    <div style="display: flex; align-items: center; margin: 1.25rem 0; color: var(--text-muted);">
        <div style="flex: 1; height: 1px; background: var(--border);"></div>
        <span style="padding: 0 0.75rem; font-size: 0.8rem; text-transform: uppercase;">or sign in with password</span>
        <div style="flex: 1; height: 1px; background: var(--border);"></div>
    </div>

    <form id="login-form" method="post" action="login.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address -->
        <div class="form-group">
            <label for="identity">Gmail Address</label>
            <input class="form-control" type="text" id="identity" name="identity"
                   value="<?php echo e($identity); ?>"
                   required maxlength="100">
        </div>

        <!-- Password -->
        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.45rem;">
                <label for="password" style="margin-bottom:0;">Password</label>
                <a id="forgot-link" href="forgot_password.php" style="font-size: 0.85rem; color: var(--primary); text-decoration: none;">Forgot Password?</a>
            </div>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password"
                       name="password"
                       required maxlength="255">
                <button type="button" class="toggle-password"
                        data-target="password" aria-label="Show or hide password"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg></button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary">Sign In &rarr;</button>

        <p class="form-footer">
            Don't have an account? <a href="register.php">Register here</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>


