<?php
/**
 * ============================================================================
 *  login.php — SECURE SIGN-IN PAGE (DIRECT AUTHENTICATION)
 * ============================================================================
 *  Fields:
 *      1. Name or Email Address
 *      2. Password
 *
 *  Flow:
 *      - Server-side lookup by Username (Full Name) OR Email address.
 *      - Prepared SQL Query (`SELECT id, fullname, email, phone, password, role FROM users WHERE LOWER(email) = ? OR LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1`).
 *      - `password_verify()` check.
 *      - Generic error: "Invalid credentials." for any failure.
 *      - On success: Regenerates Session ID -> Stores session -> Redirects directly to `dashboard.php`.
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
        } elseif (is_login_locked($possibleEmail) || is_login_locked($rawIdentity)) {
            $lockTime = get_lock_remaining($possibleEmail);
            $error    = 'Too many login attempts. Please try again later.';
        } else {
            // Prepared Statement: lookup user by Email OR Username
            $stmt = $conn->prepare('SELECT id, fullname, email, phone, password, role FROM users WHERE LOWER(email) = ? OR LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1');
            $stmt->bind_param('sss', $rawIdentity, $possibleEmail, $cleanIdentity);
            $stmt->execute();
            $result = $stmt->get_result();
            $user   = $result->fetch_assoc();
            $stmt->close();

            $passwordOk = $user !== null && password_verify($password, $user['password']);

            if ($passwordOk) {
                reset_failed_attempts($possibleEmail);
                reset_failed_attempts($rawIdentity);

                // Regenerate session ID (Session Fixation protection)
                regenerate_session();

                // Populate session identity
                $_SESSION['user_id']  = $user['id'];
                $_SESSION['fullname'] = $user['fullname'];
                $_SESSION['email']    = $user['email'];
                $_SESSION['phone']    = $user['phone'];
                $_SESSION['role']     = $user['role'];

                // Redirect directly to protected dashboard
                header('Location: dashboard.php');
                exit;
            } else {
                record_failed_attempt($possibleEmail);
                record_failed_attempt($rawIdentity);
                $error = 'Invalid credentials.';
            }
        }
    }
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
                $minutes = (int) ceil($lockTime / 60);
                echo ' <strong>Try again in about ' . $minutes . ' minute' . ($minutes > 1 ? 's' : '') . '.</strong>';
            }
            ?>
        </div>
    <?php endif; ?>

    <form id="login-form" method="post" action="login.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address (@gmail.com Fixed Right Addon) -->
        <div class="form-group">
            <label for="identity">Gmail Address</label>
            <div class="input-group">
                <input class="form-control has-addon-right" type="text" id="identity" name="identity"
                       value="<?php echo e($identity); ?>"
                       required maxlength="100">
                <span class="input-addon-right">@gmail.com</span>
            </div>
        </div>

        <!-- Password -->
        <div class="form-group">
            <label for="password">Password</label>
            <div class="password-wrap">
                <input class="form-control" type="password" id="password"
                       name="password"
                       required maxlength="255">
                <button type="button" class="toggle-password"
                        data-target="password" aria-label="Show or hide password">&#128065;</button>
            </div>
        </div>

        <button type="submit" class="btn btn-primary">Sign In &rarr;</button>

        <p class="form-footer">
            No account yet? <a href="register.php">Create an account here</a>
        </p>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
