<?php
/**
 * ============================================================================
 *  register.php — SECURE USER REGISTRATION PAGE
 * ============================================================================
 *  Fields:
 *      1. Full Name / Username (12 to 15 characters)
 *      2. Email Address (Username + fixed "@gmail.com" addon)
 *      3. Phone Number (Fixed "+91" addon + 10 digits)
 *      4. Password (Min 8 chars: Uppercase, Lowercase, Number, Special Char)
 *      5. Confirm Password
 *
 *  Flow:
 *      - Validate inputs on server-side.
 *      - Hash password securely using password_hash().
 *      - Insert into users table using Prepared Statement.
 *      - Redirect to login.php with success flash message.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$fullname    = '';
$emailPrefix = '';
$phoneNum    = '';
$error       = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $fullname        = trim($_POST['fullname'] ?? '');
        $rawPrefix       = trim($_POST['email_prefix'] ?? '');
        $phoneNum        = trim($_POST['phone_num'] ?? '');
        $password        = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        $cleanPrefix = preg_replace('/@gmail\.com$/i', '', $rawPrefix);
        $emailPrefix = $cleanPrefix;
        $email       = strtolower($cleanPrefix . '@gmail.com');
        $phone       = '+91' . $phoneNum;

        $nameLen      = mb_strlen($fullname, 'UTF-8');
        $isValidEmail = is_valid_gmail($cleanPrefix, $email);
        $isValidPhone = (bool) preg_match('/^[0-9]{10}$/', $phoneNum);
        $pwdErrors    = validate_password_strength($password);

        if ($nameLen < 12 || $nameLen > 15) {
            $error = 'Full Name / Username must be between 12 and 15 characters long.';
        } elseif (!$isValidEmail) {
            $error = 'Invalid credentials.';
        } elseif (!$isValidPhone) {
            $error = 'Please enter a valid 10-digit mobile number for +91.';
        } elseif (!empty($pwdErrors)) {
            $error = implode(' ', $pwdErrors);
        } elseif ($password !== $confirmPassword) {
            $error = 'Passwords do not match.';
        } else {
            // Check if email already registered
            $checkStmt = $conn->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
            $checkStmt->bind_param('s', $email);
            $checkStmt->execute();
            $res = $checkStmt->get_result();
            $exists = $res->num_rows > 0;
            $checkStmt->close();

            if ($exists) {
                $error = 'An account with this email address already exists.';
            } else {
                // Securely hash password using bcrypt
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                // Prepared Statement: Insert new user
                $role = 'user';
                $insertStmt = $conn->prepare('INSERT INTO users (fullname, email, phone, password, role) VALUES (?, ?, ?, ?, ?)');
                $insertStmt->bind_param('sssss', $fullname, $email, $phone, $hashedPassword, $role);

                if ($insertStmt->execute()) {
                    $insertStmt->close();
                    $_SESSION['flash_success'] = 'Account created successfully! Please sign in with your credentials below.';
                    header('Location: login.php');
                    exit;
                } else {
                    $insertStmt->close();
                    $error = 'Failed to create account. Please try again.';
                }
            }
        }
    }
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

    <form id="register-form" method="post" action="register.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Full Name / Username (12 to 15 Characters) -->
        <div class="form-group">
            <label for="fullname">Full Name / Username <span style="font-weight:normal; color:var(--text-muted);">(12 to 15 characters)</span></label>
            <input class="form-control" type="text" id="fullname" name="fullname"
                   value="<?php echo e($fullname); ?>"
                   minlength="12" maxlength="15" required>
            <small style="color: var(--text-muted); font-size: 0.8rem;">Character length must be between 12 and 15 characters.</small>
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

        <!-- Phone Number (+91 Fixed Left Addon) -->
        <div class="form-group">
            <label for="phone_num">Phone Number</label>
            <div class="input-group">
                <span class="input-addon-left">+91</span>
                <input class="form-control has-addon-left" type="tel" id="phone_num" name="phone_num"
                       value="<?php echo e($phoneNum); ?>"
                       pattern="[0-9]{10}" maxlength="10" required>
            </div>
            <small style="color: var(--text-muted); font-size: 0.8rem;">Enter 10-digit Indian mobile number.</small>
        </div>

        <!-- Password (8+ Chars with All Features) -->
        <div class="form-group">
            <label for="password">Password <span style="font-weight:normal; color:var(--text-muted);">(Min 8 chars: A-Z, a-z, 0-9, special char)</span></label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password"
                       name="password"
                       required minlength="8" maxlength="255">
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
                       required minlength="8" maxlength="255">
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
