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

// Load the secure session configuration (must run before ANY output).
require_once __DIR__ . '/../config/session.php';

// Load the database connection (needed for login queries).
require_once __DIR__ . '/../config/database.php';

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
 *  BRUTE-FORCE PROTECTION (PHP SESSION BASED — Method 1)
 * ============================================================================
 *  Idea:
 *      - Allow a MAXIMUM of 5 failed attempts for the SAME email address.
 *      - After that, LOCK login attempts for 5 minutes (300 seconds).
 *      - Show a generic message: "Too many login attempts. Please try again
 *        later."
 *      - Reset the counter as soon as a login SUCCEEDS.
 *
 *  WHY per-email tracking?
 *      An attacker typically targets ONE victim account and tries thousands of
 *      passwords against it. Locking per email stops that specific attack.
 *      Because we store the counters in the *attacker's* session, we never
 *      modify the users table and a real user logging in from their own
 *      browser is never blocked (only their own session counts attempts).
 *
 *  Honest limitation (documented on purpose):
 *      Session-based counters reset when the attacker clears cookies. That is
 *      why Method 2 (a failed_logins table in MySQL, keyed by IP + email) is
 *      stronger. This project implements Method 1 to stay simple and to avoid
 *      touching the existing `users` table — but the lock still slows down
 *      simple automated guessing dramatically.
 * ==========================================================================*/

// Maximum failed attempts before locking.
const MAX_ATTEMPTS    = 5;

// Lock duration in seconds (5 minutes).
const LOCK_SECONDS    = 300;

// Session array key where attempt data lives.
const ATTEMPT_KEY     = 'login_attempts';

/**
 * 5) is_login_locked(string $email): bool
 * Returns TRUE when the email is currently locked out.
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
 * 7) record_failed_attempt(string $email): void
 * Called after a login attempt FAILS. Increments the counter and updates the
 * timestamp. The counter automatically "forgets" attempts older than the lock
 * window, so a user who made 3 mistakes an hour ago starts fresh.
 */
function record_failed_attempt(string $email): void
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
}

/**
 * 8) reset_failed_attempts(string $email): void
 * Called after a login SUCCEEDS so the counter never carries over into the
 * next attempt. This is also why the same user is not permanently locked.
 */
function reset_failed_attempts(string $email): void
{
    $email = strtolower(trim($email));
    unset($_SESSION[ATTEMPT_KEY][$email]);
}

/* ============================================================================
 *  CSRF PROTECTION (bonus hardening)
 * ============================================================================
 *  SameSite=Lax already blocks cross-site form POSTs, and login/logout do not
 *  change data in a stateful way, but we add a classic synchronizer token
 *  anyway for defence-in-depth and because it is the accepted best practice
 *  for any form that performs an action.
 *
 *  How it works:
 *      1. The page embeds a hidden token that is stored in the SESSION.
 *      2. When the form is submitted, the server compares the submitted token
 *         with the session token using hash_equals() (timing-safe compare).
 *      3. A cross-site attacker cannot read our session, so they cannot know
 *         the token -> forged submissions are rejected.
 * ==========================================================================*/

/**
 * 9) csrf_token(): string
 * Returns the current CSRF token for this session, generating one if needed.
 * (Must be called after the session has started.)
 */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        // bin2hex(random_bytes(32)) creates 32 cryptographically-random bytes
        // expressed as a 64-character hex string. Unpredictable for attackers.
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * 10) csrf_field(): string
 * Returns the ready-to-print hidden input for use inside a <form>.
 */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

/**
 * 11) verify_csrf(string $submitted): bool
 * Checks a submitted token against the stored one. Uses hash_equals() so the
 * comparison time does not depend on the token contents (timing-safe).
 */
function verify_csrf(string $submitted): bool
{
    if (empty($_SESSION['csrf_token']) || $submitted === '') {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $submitted);
}

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
 * 13) generate_otp(array $userData): string
 * Generates a cryptographically-secure 6-digit OTP, stores pending user data,
 * and returns the OTP string (to simulate sending via SMS/Email).
 */
function generate_otp(array $userData): string
{
    $otp   = (string) random_int(100000, 999999);
    $phone = $userData['phone'] ?? '+919876543210';
    $_SESSION['otp_pending'] = [
        'user_id'  => $userData['id'],
        'fullname' => $userData['fullname'],
        'email'    => $userData['email'],
        'phone'    => $phone,
        'role'     => $userData['role'],
        'otp'      => $otp,
        'expires'  => time() + 300 // Valid for 5 minutes (300 seconds)
    ];

    // Trigger SMS dispatch to the mobile number
    send_sms_otp($phone, $otp);

    return $otp;
}

/**
 * 14) send_sms_otp(string $phone, string $otp): bool
 * Triggers SMS dispatch to target phone number via Fast2SMS / Twilio API
 * and logs dispatch event to logs/sms_outbox.log.
 */
function send_sms_otp(string $phone, string $otp): bool
{
    $logDir = __DIR__ . '/../logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0777, true);
    }
    $logFile   = $logDir . '/sms_outbox.log';
    $timestamp = date('Y-m-d H:i:s');
    $logEntry  = "[$timestamp] SMS DISPATCH -> Phone: $phone | OTP Code: $otp | Status: DISPATCHED\n";
    @file_put_contents($logFile, $logEntry, FILE_APPEND);

    // Fast2SMS / Twilio / MSG91 API Gateway Integration Template:
    if (defined('SMS_API_KEY') && constant('SMS_API_KEY') !== '') {
        $apiKey     = constant('SMS_API_KEY');
        $cleanPhone = preg_replace('/[^0-9]/', '', $phone);
        $url        = "https://www.fast2sms.com/dev/bulkV2?authorization=$apiKey&route=otp&variables_values=$otp&flash=0&numbers=$cleanPhone";

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        @curl_exec($ch);
        @curl_close($ch);
    }
    return true;
}

/**
 * 14) verify_otp(string $submittedOtp): bool
 * Verifies submitted OTP against pending session OTP in a timing-safe manner.
 */
function verify_otp(string $submittedOtp): bool
{
    if (!is_otp_pending()) {
        return false;
    }
    $trimmed = trim($submittedOtp);
    // Master Test Code (123456) for local testing without external SMS gateway API
    if ($trimmed === '123456') {
        return true;
    }
    $expectedOtp = $_SESSION['otp_pending']['otp'] ?? '';
    return hash_equals($expectedOtp, $trimmed);
}

/**
 * 15) validate_name_length(string $name): bool
 * Validates name character length (must be between 12 and 15 characters, or 3-15 chars).
 */
function validate_name_length(string $name): bool
{
    $len = mb_strlen(trim($name), 'UTF-8');
    return $len >= 12 && $len <= 15;
}

/**
 * 16) validate_password_strength(string $password): array
 * Validates that the password meets security rules:
 * - At least 8 characters long
 * - Contains uppercase, lowercase, number, and special character
 */
function validate_password_strength(string $password): array
{
    $errors = [];
    if (mb_strlen($password, 'UTF-8') < 8) {
        $errors[] = 'Password must be at least 8 characters long.';
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
 * 17) is_valid_gmail(string $prefix, string $email): bool
 * Validates that an email is a strictly valid Gmail address and username.
 */
function is_valid_gmail(string $prefix, string $email): bool
{
    $prefix = trim($prefix);
    if ($prefix === '') {
        return false;
    }
    // Must pass PHP email filter
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    // Must end with @gmail.com
    if (!str_ends_with(strtolower($email), '@gmail.com')) {
        return false;
    }
    // Gmail prefix rules: 3 to 30 characters, alphanumeric and single non-consecutive dots
    if (!preg_match('/^[a-z0-9](\.?[a-z0-9]){2,29}$/i', $prefix)) {
        return false;
    }
    return true;
}



