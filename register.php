<?php
/**
 * ============================================================================
 *  register.php — SECURE USER REGISTRATION PAGE
 * ============================================================================
 *  Fields:
 *      1. Full Name / Username
 *      2.  Address (Username + fixed "@gmail.com" addon)
 *      3. Password (Min 8 chars: Uppercase, Lowercase, Number, Special Char)
 *      4. Confirm Password
 *
 *  Flow:
 *      - Validate inputs on server-side.
 *      - Hash password securely using password_hash().
 *      - Insert into users table using Prepared Statement.
 *      - Redirect to login.php with verification flash message.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$fullname    = '';
$emailPrefix = '';
$error       = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $fullname        = trim($_POST['fullname'] ?? '');
        $rawPrefix       = trim($_POST['email_prefix'] ?? '');
        $password        = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        // Normalize input: remove @gmail.com if user entered it, convert to lowercase
        $cleanPrefix = preg_replace('/@gmail\.com$/i', '', $rawPrefix);
        $emailPrefix = strtolower(trim($cleanPrefix));

        $email       = $emailPrefix . '@gmail.com';
        $gmailError  = '';
        $isValidEmail = is_proper_gmail($email, $gmailError);

        $pwdErrors = validate_password_strength($password);

        if (!validate_name_length($fullname)) {
            $error = 'Invalid credentials.';
        } elseif (!$isValidEmail) {
            $error = 'Invalid credentials.';
        } elseif (!empty($pwdErrors)) {
            $error = 'Invalid credentials.';
        } elseif ($password !== $confirmPassword) {
            $error = 'Invalid credentials.';
        } else {
            // Check if email already registered
            $checkStmt = $conn->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
            $checkStmt->bind_param('s', $email);
            $checkStmt->execute();
            $res = $checkStmt->get_result();
            $exists = $res->num_rows > 0;
            $checkStmt->close();

            if ($exists) {
                $error = 'Invalid credentials.';
            } else {
                // Securely hash password using bcrypt
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                // Generate secure random verification token (expires in 24 hours)
                $verifyToken   = generate_secure_token(32);
                $verifyExpires = date('Y-m-d H:i:s', time() + 86400);

                // Prepared Statement: Insert new user with email_verified = 0
                $role = 'user';
                $insertStmt = $conn->prepare('INSERT INTO users (fullname, email, password, role, email_verified) VALUES (?, ?, ?, ?, 0)');
                $insertStmt->bind_param('ssss', $fullname, $email, $hashedPassword, $role);

                if ($insertStmt->execute()) {
                    $newUserId = $insertStmt->insert_id;
                    $insertStmt->close();

                    // Generate 6-digit OTP, store salted hash in MySQL, and dispatch Gmail SMTP email
                    send_verification_otp($newUserId, $email, $fullname);

                    // Redirect to OTP Verification page
                    header('Location: otp_verify.php?registered=1');
                    exit;
                } else {
                    $insertStmt->close();
                    $error = 'Invalid credentials.';
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

$pageTitle = 'Register Account — Secure Auth System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card card-wide">
    <h2>Create Your Account</h2>
    <p class="card-sub">Fill in your details below to register a new account.</p>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
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

    <form id="register-form" method="post" action="register.php" autocomplete="off">
        <?php echo csrf_field(); ?>


        <div class="form-group">
            <label for="fullname">Profile Name <span style="font-weight:normal; color:var(--text-muted);">(3-20 chars)</span></label>
            <input class="form-control" type="text" id="fullname" name="fullname"
                   value="<?php echo e($fullname); ?>"
                   minlength="3" maxlength="20" required>
        </div>

        <!-- Email Address (@gmail.com Fixed Right Addon) -->
        <div class="form-group">
            <label for="email_prefix">Email Address</label>
            <div class="input-group">
                <input class="form-control has-addon-right" type="text" id="email_prefix" name="email_prefix"
                       value="<?php echo e($emailPrefix); ?>"
                       required maxlength="100">
                <span class="input-addon-right">@gmail.com</span>
            </div>
        </div>

        <!-- Password (8 to 12 Chars with All Features) -->
        <div class="form-group">
            <label for="password">Password <span style="font-weight:normal; color:var(--text-muted);">(8-12 chars: A-Z, a-z, 0-9, special char)</span></label>
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
            <label for="confirm_password">Confirm Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="confirm_password"
                       name="confirm_password"
                       required minlength="8" maxlength="12">
                <button type="button" class="toggle-password"
                        data-target="confirm_password" aria-label="Show or hide password">&#128065;</button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary">Create Account &rarr;</button>

        <p class="form-footer">
            Already have an account? <a href="login.php">Sign In here</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
