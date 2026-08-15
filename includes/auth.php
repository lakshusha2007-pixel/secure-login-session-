<?php
/**
 * ============================================================================
 *  includes/auth.php — AUTHENTICATION HELPERS & BRUTE-FORCE PROTECTION
 * ============================================================================
 *
 *  This file contains ALL the reusable authentication logic:
 *
 *      1. e()                        – XSS-safe output helper
 *      2. is_logged_in()             – are we authenticated right now?
 *      3. require_login()            – protect a page (redirect guests)
 *      4. regenerate_session()       – defeat session fixation
 *      5. Brute-force helpers:
 *             is_login_locked()
 *             get_lock_remaining()
 *             record_failed_attempt()
 *             reset_failed_attempts()
 *      6. CSRF helpers:
 *             csrf_token()
 *             csrf_field()
 *             verify_csrf()
 *
 *  This file must be included at the very TOP of every page that needs it,
 *  BEFORE any HTML is output.
 * ============================================================================
 */

// Load modular security architecture & configuration
require_once __DIR__ . '/security.php';

// Load mail and oauth configurations
require_once __DIR__ . '/../config/mail.php';
require_once __DIR__ . '/../config/oauth.php';


/* ----------------------------------------------------------------------------
 *  0) HASHING & PASSWORD ALGORITHM HELPERS (ARGON2ID / BCRYPT)
 * ----------------------------------------------------------------------------
 *  Hashes passwords using Argon2id (`PASSWORD_ARGON2ID`) if supported by the
 *  PHP build, with fallback to bcrypt (`PASSWORD_BCRYPT` with cost 12).
 *  Salting is handled automatically and cryptographically by password_hash().
 */
function hash_password(string $password): string
{
    if (defined('PASSWORD_ARGON2ID')) {
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost'   => 4,     // 4 iterations
            'threads'     => 2,     // 2 parallelism threads
        ]);
    }
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Checks if a stored password hash needs upgrading (e.g., from bcrypt to Argon2id).
 * Upgrades the hash in the database transparently upon successful login.
 */
function check_and_upgrade_password(mysqli $conn, int $userId, string $password, string $currentHash): void
{
    $algo    = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    $options = defined('PASSWORD_ARGON2ID') ? ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2] : ['cost' => 12];

    if (password_needs_rehash($currentHash, $algo, $options)) {
        $newHash = hash_password($password);
        $stmt    = $conn->prepare('UPDATE users SET password = ? WHERE id = ?');
        if ($stmt) {
            $stmt->bind_param('si', $newHash, $userId);
            $stmt->execute();
            $stmt->close();
            log_security_event('PASSWORD_REHASH_UPGRADED', [
                'user_id' => $userId,
                'algo'    => defined('PASSWORD_ARGON2ID') ? 'Argon2id' : 'bcrypt'
            ], $userId, 'INFO');
        }
    }
}

/* ----------------------------------------------------------------------------
 *  1) e() — XSS-PREVENTION OUTPUT HELPER
 * ----------------------------------------------------------------------------
 *  NEVER print user data (email, name, anything from $_POST / database)
 *  directly into HTML. Always run it through e() first.
 *
 *  htmlspecialchars() converts dangerous characters into harmless entities:
 *      <  ->  &lt;     >  ->  &gt;     "  ->  &quot;      '  ->  &#039;
 *
 *  This means an attacker who stores <script>alert(1)</script> as their name
 *  cannot execute it — the browser just prints the raw text. This is the
 *  standard XSS (Cross-Site Scripting) defence.
 *
 *  ENT_QUOTES        : also escapes single quotes (both quote styles)
 *  'UTF-8'           : correct character set for our pages
 *  @return string    : the safely escaped text
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

/* ----------------------------------------------------------------------------
 *  2) is_logged_in()
 * ----------------------------------------------------------------------------
 *  A user counts as "logged in" ONLY if our server-side session actually
 *  holds a user_id. We never trust a cookie alone — the session data lives
 *  on the server, so a visitor cannot just forge a "logged in" cookie.
 */
function is_logged_in(): bool
{
    return isset($_SESSION['user_id']);
}

/* ----------------------------------------------------------------------------
 *  3) require_login() — GUARD FOR PROTECTED PAGES
 * ----------------------------------------------------------------------------
 *  Call this as the FIRST line of any protected page (e.g. dashboard.php).
 *
 *  If the visitor is NOT logged in we redirect them to login.php and
 *  immediately stop execution with exit; so the rest of the page can never
 *  load. header() only works when no output has been sent yet, which is why
 *  this must run before any HTML.
 */
function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: login.php');
        exit;
    }
}

/* ----------------------------------------------------------------------------
 *  4) regenerate_session() — DEFEAT SESSION FIXATION
 * ----------------------------------------------------------------------------
 *  session_regenerate_id(true):
 *      - Gives the user a BRAND NEW, random session ID.
 *      - true  = delete the OLD session file immediately.
 *
 *  When must we call it?
 *      - Right AFTER a successful login (privilege escalation point).
 *      - Optionally on every login attempt.
 *
 *  WHY it matters:
 *  An attacker can pre-issue a known session ID to a victim. If the victim
 *  logs in without changing the ID, the attacker already knows it and can
 *  take over the account. By regenerating the ID at login, the attacker's
 *  known ID becomes useless — the session they saw never becomes privileged.
 */
function regenerate_session(): void
{
    // Never regenerate a session that hasn't been started.
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    session_regenerate_id(true);
}

/* ============================================================================
 *  BRUTE-FORCE PROTECTION (SESSION & DATABASE BASED)
 * ============================================================================
 *  Idea:
 *      - Allow a MAXIMUM of 3 failed attempts for the SAME email address / identity.
 *      - After 3 failed attempts, automatically INACTIVATE the account for
 *        24 hours (86400 seconds).
 *      - Show a generic message: "Too many login attempts. Please try again later."
 *      - Automatically reactivate after 24 hours elapse or when login SUCCEEDS.
 * ==========================================================================*/

// Maximum failed attempts before locking (3 attempts).
const MAX_ATTEMPTS    = 3;

// Inactive duration in seconds (24 hours = 86400 seconds).
const LOCK_SECONDS    = 86400;

// Session array key where attempt data lives.
const ATTEMPT_KEY     = 'login_attempts';

/**
 * 5) is_login_locked(string $email): bool
 * Returns TRUE when the email is currently locked out in session.
 */
function is_login_locked(string $email): bool
{
    // Normalise the email the same way we do when storing it.
    $email = strtolower(trim($email));

    // No history for this email -> obviously not locked.
    if (!isset($_SESSION[ATTEMPT_KEY][$email])) {
        return false;
    }

    $data = $_SESSION[ATTEMPT_KEY][$email];

    // Lock is only active if we reached the attempt limit...
    if (($data['attempts'] ?? 0) < MAX_ATTEMPTS) {
        return false;
    }

    // ...AND the lock window has not expired yet.
    $elapsed = time() - ($data['last_attempt'] ?? 0);
    return $elapsed < LOCK_SECONDS;
}

/**
 * 6) get_lock_remaining(string $email): int
 * Returns the number of SECONDS still left in the lock, or 0 if no lock.
 * Used to show the visitor a friendlier message.
 */
function get_lock_remaining(string $email): int
{
    $email = strtolower(trim($email));

    if (!isset($_SESSION[ATTEMPT_KEY][$email])) {
        return 0;
    }

    $data = $_SESSION[ATTEMPT_KEY][$email];

    if (($data['attempts'] ?? 0) < MAX_ATTEMPTS) {
        return 0;
    }

    $remaining = LOCK_SECONDS - (time() - ($data['last_attempt'] ?? 0));
    return $remaining > 0 ? $remaining : 0;
}

/**
 * 7) record_failed_attempt(string $email): int
 * Called after a login attempt FAILS. Increments the counter and updates the
 * timestamp. Returns current attempt count.
 */
function record_failed_attempt(string $email): int
{
    $email = strtolower(trim($email));

    if (!isset($_SESSION[ATTEMPT_KEY][$email])) {
        $_SESSION[ATTEMPT_KEY][$email] = [
            'attempts'     => 0,
            'last_attempt' => 0,
        ];
    }

    $data = &$_SESSION[ATTEMPT_KEY][$email];

    // Reset the counter if the previous attempts are older than the lock
    // window (keeps the counter relevant and prevents permanent lockouts).
    if (time() - ($data['last_attempt'] ?? 0) >= LOCK_SECONDS) {
        $data['attempts'] = 0;
    }

    $data['attempts']++;
    $data['last_attempt'] = time();

    return (int)$data['attempts'];
}

/**
 * 8) reset_failed_attempts(string $email): void
 * Called after a login SUCCEEDS so the counter never carries over into the
 * next attempt.
 */
function reset_failed_attempts(string $email): void
{
    $email = strtolower(trim($email));
    unset($_SESSION[ATTEMPT_KEY][$email]);
}

/**
 * 8b) is_db_account_locked(mysqli $conn, string $identity): array
 * Checks the database for the persistent 24-hour inactive state.
 * Returns ['is_locked' => bool, 'remaining' => int].
 */
function is_db_account_locked(mysqli $conn, string $identity): array
{
    $clean = strtolower(trim($identity));
    $stmt = $conn->prepare('SELECT id, failed_login_attempts, lockout_until, is_active, TIMESTAMPDIFF(SECOND, NOW(), lockout_until) AS remaining_sec FROM users WHERE LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1');
    if (!$stmt) {
        return ['is_locked' => false, 'remaining' => 0];
    }
    $stmt->bind_param('ss', $clean, $clean);
    $stmt->execute();
    $res = $stmt->get_result();
    $user = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$user) {
        return ['is_locked' => false, 'remaining' => 0];
    }

    $remainingSec = (int)($user['remaining_sec'] ?? 0);

    if ($remainingSec > 0) {
        return ['is_locked' => true, 'remaining' => $remainingSec];
    }

    // Auto-reactivate if the 24-hour inactive period has elapsed
    if ($user['lockout_until'] !== null || (int)($user['is_active'] ?? 1) === 0) {
        $resetStmt = $conn->prepare('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, is_active = 1 WHERE id = ?');
        if ($resetStmt) {
            $resetStmt->bind_param('i', $user['id']);
            $resetStmt->execute();
            $resetStmt->close();
        }
    }

    return ['is_locked' => false, 'remaining' => 0];
}

/**
 * 8c) record_db_failed_attempt(mysqli $conn, string $identity): int
 * Increments failed_login_attempts in users table and inactivates the account for
 * 24 hours when reaching MAX_ATTEMPTS (3). Returns updated attempt count.
 */
function record_db_failed_attempt(mysqli $conn, string $identity): int
{
    $clean = strtolower(trim($identity));
    $stmt = $conn->prepare('SELECT id, failed_login_attempts, lockout_until, TIMESTAMPDIFF(SECOND, NOW(), lockout_until) AS remaining_sec FROM users WHERE LOWER(email) = ? OR LOWER(fullname) = ? LIMIT 1');
    if (!$stmt) {
        return 0;
    }
    $stmt->bind_param('ss', $clean, $clean);
    $stmt->execute();
    $res = $stmt->get_result();
    $user = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$user) {
        return 0;
    }

    $remainingSec = (int)($user['remaining_sec'] ?? 0);
    $attempts = (int)$user['failed_login_attempts'];

    if ($user['lockout_until'] !== null && $remainingSec <= 0) {
        $attempts = 0;
    }

    $attempts++;

    if ($attempts >= MAX_ATTEMPTS) {
        $upd = $conn->prepare('UPDATE users SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 24 HOUR), is_active = 0 WHERE id = ?');
        if ($upd) {
            $upd->bind_param('ii', $attempts, $user['id']);
            $upd->execute();
            $upd->close();
        }
    } else {
        $upd = $conn->prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?');
        if ($upd) {
            $upd->bind_param('ii', $attempts, $user['id']);
            $upd->execute();
            $upd->close();
        }
    }

    return $attempts;
}

/**
 * 8d) reset_db_failed_attempts(mysqli $conn, int $userId): void
 * Clears failed login attempts and reactivates the account upon successful login.
 */
function reset_db_failed_attempts(mysqli $conn, int $userId): void
{
    $stmt = $conn->prepare('UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, is_active = 1 WHERE id = ?');
    if ($stmt) {
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $stmt->close();
    }
}

/* ============================================================================
 *  CSRF Protection is loaded via includes/csrf.php
 * ============================================================================ */


/* ============================================================================
 *  OTP (TWO-FACTOR AUTHENTICATION) HELPERS
 * ============================================================================
 */

/**
 * 12) is_otp_pending(): bool
 * Checks whether an unverified 2FA OTP state is active in the session.
 */
function is_otp_pending(): bool
{
    if (empty($_SESSION['otp_pending'])) {
        return false;
    }
    $pending = $_SESSION['otp_pending'];
    if (time() > ($pending['expires'] ?? 0)) {
        unset($_SESSION['otp_pending']);
        return false;
    }
    return true;
}

/**
 * 13) generate_6digit_otp(): string
 * Generates a cryptographically-secure 6-digit numeric OTP string.
 */
function generate_6digit_otp(): string
{
    return (string) random_int(100000, 999999);
}

/**
 * 14) can_resend_otp(int $userId): int
 * Checks if 60-second OTP resend cooldown is active. Returns remaining seconds (0-60).
 */
function can_resend_otp(int $userId): int
{
    global $conn;
    $stmt = $conn->prepare('SELECT TIMESTAMPDIFF(SECOND, otp_last_sent, NOW()) AS elapsed FROM users WHERE id = ? LIMIT 1');
    if (!$stmt) {
        return 0;
    }
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$row || $row['elapsed'] === null) {
        return 0;
    }

    $elapsed  = (int) $row['elapsed'];
    $cooldown = 60 - $elapsed;
    return ($cooldown > 0 && $cooldown <= 60) ? $cooldown : 0;
}

/**
 * 15) send_verification_otp(int $userId, string $email, string $fullname): array
 * Generates a 6-digit OTP, stores ONLY its password_hash() in MySQL, sets 60-second expiry,
 * updates otp_last_sent, and dispatches Gmail SMTP email.
 */
function send_verification_otp(int $userId, string $email, string $fullname): array
{
    global $conn;

    $cooldown = can_resend_otp($userId);
    if ($cooldown > 0) {
        return [
            'success' => false,
            'message' => "Please wait {$cooldown} second" . ($cooldown > 1 ? 's' : '') . " before requesting a new OTP code.",
            'cooldown'=> $cooldown,
        ];
    }

    $otp     = generate_6digit_otp();
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    // Store ONLY the hashed OTP in database with exact 60-second expiry
    $stmt = $conn->prepare('UPDATE users SET verification_otp_hash = ?, verification_otp_expires = DATE_ADD(NOW(), INTERVAL 60 SECOND), otp_attempts = 0, otp_last_sent = NOW() WHERE id = ?');
    $stmt->bind_param('si', $otpHash, $userId);
    $stmt->execute();
    $stmt->close();

    // Store pending session data (without storing raw OTP in session)
    $_SESSION['otp_pending'] = [
        'user_id'  => $userId,
        'fullname' => $fullname,
        'email'    => $email,
        'sent_at'  => time(),
        'expires'  => time() + 60,
    ];

    // Dispatch Gmail SMTP email with OTP
    send_otp_email($email, $fullname, $otp);

    return [
        'success' => true,
        'message' => 'A 6-digit OTP verification code has been sent to your Gmail address.',
        'cooldown'=> 60,
    ];
}

/**
 * 16) verify_email_otp(int $userId, string $inputOtp): array
 * Verifies submitted OTP against stored password_hash() in MySQL.
 * Enforces 60-second expiration, max 5 attempts, and single-use protection.
 */
function verify_email_otp(int $userId, string $inputOtp): array
{
    global $conn;

    $stmt = $conn->prepare('SELECT id, fullname, email, verification_otp_hash, verification_otp_expires, otp_attempts, TIMESTAMPDIFF(SECOND, NOW(), verification_otp_expires) AS remaining_sec FROM users WHERE id = ? LIMIT 1');
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        return ['success' => false, 'message' => 'User account not found.'];
    }

    if (empty($user['verification_otp_hash']) || empty($user['verification_otp_expires'])) {
        return ['success' => false, 'message' => 'No active OTP verification request. Please click Resend OTP to get a new code.'];
    }

    if ((int)$user['otp_attempts'] >= 5) {
        return ['success' => false, 'message' => 'Too many failed OTP attempts. Please click Resend OTP to receive a new code.'];
    }

    $remainingSec = (int)($user['remaining_sec'] ?? 0);
    if ($remainingSec <= 0) {
        return ['success' => false, 'message' => 'OTP code has expired (60-second limit reached). Please click Resend OTP to receive a new code.'];
    }

    $inputOtp = trim($inputOtp);
    $isValid  = password_verify($inputOtp, $user['verification_otp_hash']);

    if (!$isValid) {
        // Increment failed attempt counter
        $incStmt = $conn->prepare('UPDATE users SET otp_attempts = otp_attempts + 1 WHERE id = ?');
        $incStmt->bind_param('i', $userId);
        $incStmt->execute();
        $incStmt->close();

        $remaining = 5 - ((int)$user['otp_attempts'] + 1);
        return [
            'success' => false,
            'message' => "Invalid OTP code. " . ($remaining > 0 ? "You have $remaining attempt(s) remaining." : "Attempt limit reached. Please resend code."),
        ];
    }

    // SUCCESS: Mark email verified and clear single-use OTP fields
    $updateStmt = $conn->prepare('UPDATE users SET email_verified = 1, verification_otp_hash = NULL, verification_otp_expires = NULL, otp_attempts = 0 WHERE id = ?');
    $updateStmt->bind_param('i', $userId);
    $updateStmt->execute();
    $updateStmt->close();

    unset($_SESSION['otp_pending']);

    return ['success' => true, 'message' => 'Email verified successfully!'];
}

/**
 * 17) send_password_reset_otp(string $email): array
 * Generates 6-digit reset OTP for registered Gmail ID, stores salted hash (60-second expiry), and dispatches email.
 * If the Gmail ID is separate/unregistered, returns success = false with 'Invalid credentials.'.
 */
function send_password_reset_otp(string $email): array
{
    global $conn;
    $email = strtolower(trim($email));
    if (!str_contains($email, '@')) {
        $email .= '@gmail.com';
    }

    $stmt = $conn->prepare('SELECT id, fullname, email FROM users WHERE LOWER(email) = ? LIMIT 1');
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        return [
            'success' => false,
            'message' => 'Invalid credentials.',
        ];
    }

    $cooldown = can_resend_otp($user['id']);
    if ($cooldown > 0) {
        return [
            'success'  => false,
            'message'  => "Please wait {$cooldown} second" . ($cooldown > 1 ? 's' : '') . " before requesting a new OTP code.",
            'cooldown' => $cooldown,
        ];
    }

    $otp     = generate_6digit_otp();
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    $updStmt = $conn->prepare('UPDATE users SET reset_otp_hash = ?, reset_otp_expires = DATE_ADD(NOW(), INTERVAL 60 SECOND), otp_attempts = 0, otp_last_sent = NOW() WHERE id = ?');
    $updStmt->bind_param('si', $otpHash, $user['id']);
    $updStmt->execute();
    $updStmt->close();

    $_SESSION['reset_otp'] = [
        'email'    => strtolower($user['email']),
        'sent_at'  => time(),
        'lifetime' => 60,
    ];

    // Send Reset OTP email
    $subject  = 'Password Reset OTP Code — SecureAuth';
    $bodyHtml = '
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #e11d48;">Password Reset Request</h2>
        <p>Hello ' . e($user['fullname']) . ',</p>
        <p>Your 6-digit password reset OTP code for SecureAuth is:</p>
        <div style="margin: 20px 0; text-align: center;">
            <span style="font-size: 2.2rem; font-weight: 800; letter-spacing: 6px; color: #e11d48; background: #ffe4e6; padding: 10px 24px; border-radius: 8px; display: inline-block;">' . e($otp) . '</span>
        </div>
        <p style="font-size: 0.85rem; color: #64748b;">This OTP code is valid for 60 seconds. Do not share this code with anyone.</p>
    </div>';

    send_app_mail($email, $user['fullname'], $subject, $bodyHtml);

    return [
        'success' => true,
        'message' => 'A 6-digit password reset OTP code has been sent to your registered Gmail address.',
    ];
}

/**
 * 18) verify_password_reset_otp(string $email, string $inputOtp): array
 * Verifies submitted reset OTP against password_hash() in MySQL.
 */
function verify_password_reset_otp(string $email, string $inputOtp): array
{
    global $conn;
    $email = strtolower(trim($email));
    if (!str_contains($email, '@')) {
        $email .= '@gmail.com';
    }

    $stmt = $conn->prepare('SELECT id, fullname, email, reset_otp_hash, reset_otp_expires, otp_attempts, TIMESTAMPDIFF(SECOND, NOW(), reset_otp_expires) AS remaining_sec FROM users WHERE LOWER(email) = ? LIMIT 1');
    $stmt->bind_param('s', $email);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user || empty($user['reset_otp_hash']) || empty($user['reset_otp_expires'])) {
        return ['success' => false, 'message' => 'Invalid credentials.'];
    }

    if ((int)$user['otp_attempts'] >= 5) {
        return ['success' => false, 'message' => 'Too many failed OTP attempts. Please request a new password reset OTP.'];
    }

    $remainingSec = (int)($user['remaining_sec'] ?? 0);
    if ($remainingSec <= 0) {
        return ['success' => false, 'message' => 'Password reset OTP has expired (60-second limit reached). Please request a new code.'];
    }

    $inputOtp = trim($inputOtp);
    $isValid  = password_verify($inputOtp, $user['reset_otp_hash']);

    if (!$isValid) {
        $incStmt = $conn->prepare('UPDATE users SET otp_attempts = otp_attempts + 1 WHERE id = ?');
        $incStmt->bind_param('i', $user['id']);
        $incStmt->execute();
        $incStmt->close();

        return ['success' => false, 'message' => 'Invalid OTP code. Please check and try again.'];
    }

    unset($_SESSION['reset_otp']);

    return ['success' => true, 'user' => $user];
}

/**
 * 19) send_otp_email(string $email, string $fullname, string $otp): bool
 * Dispatches 6-digit OTP code to the registered email address via Gmail SMTP.
 */
function send_otp_email(string $email, string $fullname, string $otp): bool
{
    $subject  = 'Your Gmail Verification OTP Code — SecureAuth';
    $bodyHtml = '
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Gmail OTP Verification Code</h2>
        <p>Hello ' . e($fullname) . ',</p>
        <p>Your 6-digit email verification OTP code for SecureAuth is:</p>
        <div style="margin: 20px 0; text-align: center;">
            <span style="font-size: 2.2rem; font-weight: 800; letter-spacing: 6px; color: #4f46e5; background: #eef2ff; padding: 10px 24px; border-radius: 8px; display: inline-block;">' . e($otp) . '</span>
        </div>
        <p style="font-size: 0.85rem; color: #64748b;">This OTP code is valid for 60 seconds and can only be used once.</p>
        <p style="font-size: 0.85rem; color: #94a3b8;">If you did not initiate this request, please ignore this email.</p>
    </div>';

    return send_app_mail($email, $fullname, $subject, $bodyHtml);
}

/**
 * 15) validate_name_length(string $name): bool
 * Validates display name character length (must be between 3 and 20 characters, non-empty).
 */
function validate_name_length(string $name): bool
{
    $len = mb_strlen(trim($name), 'UTF-8');
    return $len >= 3 && $len <= 20;
}

/**
 * 16) validate_password_strength(string $password): array
 * Validates that the password meets security rules:
 * - Between 8 and 12 characters long
 * - Contains uppercase, lowercase, number, and special character
 */
function validate_password_strength(string $password): array
{
    $errors = [];
    $len = mb_strlen($password, 'UTF-8');
    if ($len < 8 || $len > 12) {
        $errors[] = 'Password must be between 8 and 12 characters long.';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter (A-Z).';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter (a-z).';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number (0-9).';
    }
    if (!preg_match('/[\W_]/', $password)) {
        $errors[] = 'Password must contain at least one special character (!@#$%^&*...).';
    }
    return $errors;
}

/**
 * 17) is_proper_gmail(string $email, ?string &$errorMsg = null): bool
 * Validates that an email is a strictly valid and realistic Gmail address.
 * Rejects invalid format, non-Gmail domains, syntax errors, and random key-mashing/gibberish
 * (e.g. lieruujdblvvdlfi123@gmail.com).
 */
function is_proper_gmail(string $email, ?string &$errorMsg = null): bool
{
    $email = strtolower(trim($email));

    if ($email === '') {
        $errorMsg = 'Email address is required.';
        return false;
    }

    // Must be valid email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorMsg = 'Please enter a valid email address.';
        return false;
    }

    // Must end with @gmail.com or @googlemail.com
    if (!preg_match('/@(gmail\.com|googlemail\.com)$/i', $email)) {
        $errorMsg = 'Please use a Gmail address (e.g. you@gmail.com).';
        return false;
    }

    $parts  = explode('@', $email);
    $prefix = $parts[0];
    $len    = strlen($prefix);

    // Gmail username length rule (3 to 30 characters)
    if ($len < 3 || $len > 30) {
        $errorMsg = 'Gmail username must be between 3 and 30 characters.';
        return false;
    }

    // Allowed characters: letters, numbers, dot. Dot cannot be first/last or consecutive.
    if (!preg_match('/^[a-z0-9](\.?[a-z0-9]){1,28}[a-z0-9]$/i', $prefix) && $len > 1) {
        $errorMsg = 'Gmail username can only contain letters, numbers and dots (no leading, trailing or consecutive dots).';
        return false;
    }

    // 1) Key-mashing check: 5 or more consecutive consonants (e.g., dblvvdlf in lieruujdblvvdlfi123)
    if (preg_match('/[bcdfghjklmnpqrstvwxz]{5,}/i', $prefix)) {
        $errorMsg = 'That Gmail username looks like random typing. Please enter a realistic username.';
        return false;
    }

    // 2) Keyboard row mashing patterns (e.g. qwerty, asdfgh, zxcvbn)
    $keyMashes = ['qwerty', 'wertyu', 'ertyui', 'rtyuio', 'tyuiop', 'asdfgh', 'sdfghj', 'dfghjk', 'fghjkl', 'zxcvbn', 'xcvbnm', '123456', '234567', '345678', '456789'];
    foreach ($keyMashes as $mash) {
        if (str_contains($prefix, $mash)) {
            $errorMsg = 'That Gmail username looks like a keyboard pattern (e.g. qwerty). Please choose a realistic one.';
            return false;
        }
    }

    // 3) 4 or more repeated identical characters (e.g. aaaa, 1111)
    if (preg_match('/(.)\1{3,}/', $prefix)) {
        $errorMsg = 'That Gmail username contains too many repeated characters.';
        return false;
    }

    // 4) Vowel presence check for long letter-only sequences (6+ letters without any vowels)
    $lettersOnly = preg_replace('/[^a-z]/i', '', $prefix);
    if (strlen($lettersOnly) >= 6) {
        $vowelsCount = preg_match_all('/[aeiouy]/i', $lettersOnly);
        if ($vowelsCount === 0) {
            $errorMsg = 'That Gmail username is not realistic. Please enter a proper name.';
            return false;
        }
    }

    return true;
}

/**
 * 17b) is_valid_gmail(string $prefix, string $email): bool
 * Validates that an email is a strictly valid Gmail address and username.
 */
function is_valid_gmail(string $prefix, string $email): bool
{
    return is_proper_gmail($email);
}

/**
 * 18) generate_secure_token(int $length = 32): string
 * Generates a cryptographically-secure random hex token.
 */
function generate_secure_token(int $length = 32): string
{
    return bin2hex(random_bytes($length));
}

/**
 * 19) send_verification_email(string $email, string $fullname, string $token): bool
 * Sends an email verification link to the user.
 */
function send_verification_email(string $email, string $fullname, string $token): bool
{
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    $verifyUrl = $protocol . '://' . $host . '/verify_email.php?token=' . urlencode($token);

    $subject  = 'Verify Your Email Address — SecureAuth';
    $bodyHtml = '
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Welcome to SecureAuth, ' . e($fullname) . '!</h2>
        <p>Thank you for registering. Please verify your email address to activate your account:</p>
        <div style="margin: 25px 0;">
            <a href="' . e($verifyUrl) . '" style="background: #4f46e5; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Verify Email Address &rarr;</a>
        </div>
        <p style="font-size: 0.85rem; color: #64748b;">If the button above does not work, copy and paste this link into your browser:<br>
        <a href="' . e($verifyUrl) . '">' . e($verifyUrl) . '</a></p>
        <p style="font-size: 0.85rem; color: #94a3b8;">This verification link will expire in 24 hours.</p>
    </div>';

    return send_app_mail($email, $fullname, $subject, $bodyHtml, $verifyUrl);
}

/**
 * 20) send_password_reset_email(string $email, string $fullname, string $rawToken): bool
 * Sends a password reset link to the user.
 */
function send_password_reset_email(string $email, string $fullname, string $rawToken): bool
{
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    $resetUrl = $protocol . '://' . $host . '/reset_password.php?token=' . urlencode($rawToken);

    $subject  = 'Password Reset Request — SecureAuth';
    $bodyHtml = '
    <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
        <h2 style="color: #4f46e5;">Password Reset Request</h2>
        <p>Hello ' . e($fullname) . ',</p>
        <p>We received a request to reset your password for your SecureAuth account. Click the button below to set a new password:</p>
        <div style="margin: 25px 0;">
            <a href="' . e($resetUrl) . '" style="background: #e11d48; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password &rarr;</a>
        </div>
        <p style="font-size: 0.85rem; color: #64748b;">If you did not request a password reset, you can safely ignore this email.</p>
        <p style="font-size: 0.85rem; color: #94a3b8;">This link is single-use and expires in 1 hour.</p>
    </div>';

    return send_app_mail($email, $fullname, $subject, $bodyHtml, $resetUrl);
}

/**
 * Enforces server-side Step-Up Authentication (Password Re-Verification).
 * Redirects user to step_up.php?return_to=... if elevated authentication state
 * is expired (older than $maxAgeSeconds, default 300 seconds / 5 minutes).
 */
function require_step_up(int $maxAgeSeconds = 300): void
{
    require_login();

    $lastVerifiedAt = (int)($_SESSION['last_password_verified_at'] ?? 0);
    $elapsed = time() - $lastVerifiedAt;

    if ($lastVerifiedAt === 0 || $elapsed > $maxAgeSeconds) {
        $requestUri = $_SERVER['REQUEST_URI'] ?? 'dashboard.php';
        log_security_event('STEP_UP_AUTHENTICATION_REQUIRED', [
            'user_id'     => $_SESSION['user_id'] ?? null,
            'request_uri' => $requestUri,
            'elapsed_sec' => $elapsed
        ], $_SESSION['user_id'] ?? null, 'INFO');

        // Resolve path to step_up.php cleanly
        $scriptPath = $_SERVER['SCRIPT_NAME'] ?? '';
        $prefix = (str_contains($scriptPath, '/api/') || str_contains($scriptPath, '/admin/')) ? '../' : '';

        header('Location: ' . $prefix . 'step_up.php?return_to=' . urlencode($requestUri));
        exit;
    }
}

/**
 * Automated token and log retention purge.
 */
function purge_expired_tokens_and_logs(mysqli $conn): void
{
    try {
        $conn->query('UPDATE users SET verification_otp_hash = NULL, verification_otp_expires = NULL WHERE verification_otp_expires IS NOT NULL AND verification_otp_expires < NOW()');
        $conn->query('UPDATE users SET reset_otp_hash = NULL, reset_otp_expires = NULL WHERE reset_otp_expires IS NOT NULL AND reset_otp_expires < NOW()');
        $conn->query('DELETE FROM password_resets WHERE expires_at < NOW()');
        $conn->query('DELETE FROM rate_limits WHERE lockout_until IS NOT NULL AND lockout_until < NOW()');
        $conn->query("DELETE FROM security_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)");
    } catch (Throwable $e) {
        error_log('Token purge failed: ' . $e->getMessage());
    }
}






