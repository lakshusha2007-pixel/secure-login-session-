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
 *      - Email verification check (`email_verified = 1`).
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
        error_log('CSRF token mismatch on login page from IP ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $error = 'Invalid credentials.';
    } else {
        $identity = trim($_POST['identity'] ?? '');
        $password = $_POST['password'] ?? '';

        // Formulate potential email address (append @gmail.com if prefix provided)
        $cleanIdentity = preg_replace('/@gmail\.com$/i', '', $identity);
        $possibleEmail = strtolower($cleanIdentity . '@gmail.com');
        $rawIdentity   = strtolower($identity);

        if ($identity === '' || $password === '') {
            $error = 'Invalid credentials.';
        } else {
            $dbLock = is_db_account_locked($conn, $identity);
            $sessLock1 = is_login_locked($possibleEmail);
            $sessLock2 = is_login_locked($rawIdentity);

            if ($dbLock['is_locked'] || $sessLock1 || $sessLock2) {
                $lockTime = max($dbLock['remaining'], get_lock_remaining($possibleEmail), get_lock_remaining($rawIdentity));
                $error    = 'Too many login attempts. Account is inactive for 20 minutes.';
            } else {
                // Prepared Statement: lookup user by Email OR Username
                $stmt = $conn->prepare('SELECT id, fullname, email, phone, password, role, email_verified FROM users WHERE LOWER(email) = ? OR LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1');
                $stmt->bind_param('sss', $rawIdentity, $possibleEmail, $cleanIdentity);
                $stmt->execute();
                $result = $stmt->get_result();
                $user   = $result->fetch_assoc();
                $stmt->close();

                $passwordOk = $user !== null && password_verify($password, $user['password']);

                if ($passwordOk) {
                    reset_failed_attempts($possibleEmail);
                    reset_failed_attempts($rawIdentity);
                    reset_db_failed_attempts($conn, (int)$user['id']);

                    // Generate fresh 6-digit Gmail Verification OTP code & send via SMTP
                    send_verification_otp((int)$user['id'], $user['email'], $user['fullname']);

                    // Redirect user to Gmail OTP verification page
                    header('Location: otp_verify.php?sent=1');
                    exit;
                } else {
                    $att1  = record_failed_attempt($possibleEmail);
                    $att2  = record_failed_attempt($rawIdentity);
                    $dbAtt = record_db_failed_attempt($conn, $identity);

                    $currentAttempts = max($att1, $att2, $dbAtt);

                    if ($currentAttempts >= MAX_ATTEMPTS) {
                        $dbLock   = is_db_account_locked($conn, $identity);
                        $lockTime = max($dbLock['remaining'], get_lock_remaining($possibleEmail), get_lock_remaining($rawIdentity), LOCK_SECONDS);
                        $error    = 'Too many login attempts (Attempt 3 of 3 failed). Account is inactive for 20 minutes.';
                    } elseif ($currentAttempts === 2) {
                        $error    = 'Invalid credentials (Attempt 2 of 3 failed). You have 1 attempt remaining.';
                    } else {
                        $error    = 'Invalid credentials (Attempt 1 of 3 failed). You have 2 attempts remaining.';
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
    <p class="card-sub">Enter your Gmail username or Full Name and password to continue.</p>

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
    <div style="margin-bottom: 1.5rem;">
        <a class="btn btn-google" href="<?php echo e($googleAuthUrl); ?>" style="display: flex; align-items: center; justify-content: center; gap: 0.75rem; width: 100%; padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid #cbd5e1; background: #ffffff; color: #1e293b; font-weight: 600; text-decoration: none; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
            <svg width="20" height="20" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            Continue with Google
        </a>
    </div>

    <div style="display: flex; align-items: center; margin: 1.5rem 0; color: var(--text-muted, #94a3b8);">
        <div style="flex: 1; height: 1px; background: #e2e8f0;"></div>
        <span style="padding: 0 0.75rem; font-size: 0.85rem; text-transform: uppercase;">or</span>
        <div style="flex: 1; height: 1px; background: #e2e8f0;"></div>
    </div>

    <form id="login-form" method="post" action="login.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address (@gmail.com Fixed Right Addon) -->
        <div class="form-group">
            <label for="identity">Gmail Address / Username</label>
            <div class="input-group">
                <input class="form-control has-addon-right" type="text" id="identity" name="identity"
                       value="<?php echo e($identity); ?>"
                       required maxlength="100">
                <span class="input-addon-right">@gmail.com</span>
            </div>
        </div>

        <!-- Password -->
        <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem;">
                <label for="password" style="margin-bottom:0;">Password</label>
                <a id="forgot-link" href="forgot_password.php" style="font-size: 0.85rem; color: #4f46e5; text-decoration: none;">Forgot Password?</a>
            </div>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password"
                       name="password"
                       required minlength="8" maxlength="12">
                <button type="button" class="toggle-password"
                        data-target="password" aria-label="Show or hide password">&#128065;</button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary">Sign In &rarr;</button>

        <p class="form-footer">
            Don't have an account? <a href="register.php">Register</a>
        </p>
    </form>
</div>

<script>
(function() {
    var identityInput = document.getElementById('identity');
    var forgotLink = document.getElementById('forgot-link');
    
    function updateForgotLink() {
        if (!identityInput || !forgotLink) return;
        var val = identityInput.value.trim();
        if (val !== '') {
            if (val.indexOf('@') === -1) {
                val += '@gmail.com';
            }
            forgotLink.href = 'forgot_password.php?login_email=' + encodeURIComponent(val);
        } else {
            forgotLink.href = 'forgot_password.php';
        }
    }
    
    if (identityInput) {
        identityInput.addEventListener('input', updateForgotLink);
        updateForgotLink();
    }
})();
</script>

<?php require_once __DIR__ . '/includes/footer.php'; ?>

