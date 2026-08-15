<?php
/**
 * ============================================================================
 *  oauth_callback.php — OAUTH 2.0 CALLBACK HANDLER (GOOGLE)
 * ============================================================================
 *  Handles Google OAuth 2.0 redirect response, validates state token CSRF,
 *  retrieves user profile, links existing email accounts or creates new users,
 *  and establishes a secure PHP session.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

$code  = $_GET['code'] ?? '';
$state = $_GET['state'] ?? '';
$error = $_GET['error'] ?? '';

// If user cancelled or OAuth error returned
if ($error !== '') {
    $_SESSION['flash_error'] = 'Google Sign-In was cancelled or failed.';
    header('Location: login.php');
    exit;
}

// CSRF State token validation
if ($state === '' || !verify_csrf($state)) {
    $_SESSION['flash_error'] = 'Invalid OAuth security state token. Please try again.';
    header('Location: login.php');
    exit;
}

if ($code === '') {
    $_SESSION['flash_error'] = 'Missing authorization code from Google.';
    header('Location: login.php');
    exit;
}

// Fetch Google User Profile
$googleUser = fetch_google_user_info($code);

if (!$googleUser) {
    // If real credentials are placeholder or network failed in local dev, provide simulated test login flow
    if (GOOGLE_CLIENT_ID === 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com') {
        // Localhost Demonstration Mode when client ID is placeholder
        $googleUser = [
            'sub'           => 'google_demo_109238471923',
            'email'         => 'demo@gmail.com',
            'name'          => 'Demo User',
            'email_verified'=> true,
        ];
    } else {
        $_SESSION['flash_error'] = 'Failed to retrieve user profile from Google. Please verify OAuth client configuration.';
        header('Location: login.php');
        exit;
    }
}

$googleId    = $googleUser['sub'] ?? '';
$googleEmail = strtolower(trim($googleUser['email'] ?? ''));
$googleName  = trim($googleUser['name'] ?? 'Google User');

if ($googleEmail === '') {
    $_SESSION['flash_error'] = 'Google account did not provide a valid email address.';
    header('Location: login.php');
    exit;
}

if (empty($googleUser['email_verified'])) {
    $_SESSION['flash_error'] = 'This Google account email is not verified. Please verify it with Google and try again.';
    header('Location: login.php');
    exit;
}

// 1. Look up existing user by email address or google_id
$stmt = $conn->prepare('SELECT id, fullname, email, phone, role, email_verified, google_id, is_active FROM users WHERE LOWER(email) = ? OR (google_id IS NOT NULL AND google_id = ?) LIMIT 1');
$stmt->bind_param('ss', $googleEmail, $googleId);
$stmt->execute();
$existingUser = $stmt->get_result()->fetch_assoc();
$stmt->close();

if ($existingUser && (int)($existingUser['is_active'] ?? 1) === 0) {
    $_SESSION['flash_error'] = 'Your account is currently inactive. Please try again after 24 hours.';
    header('Location: login.php');
    exit;
}

if ($existingUser) {
    // Existing user (verified or unverified) -> Link google_id and mark email_verified = 1
    $userId = $existingUser['id'];
    $updateStmt = $conn->prepare('UPDATE users SET email_verified = 1, google_id = ? WHERE id = ?');
    $updateStmt->bind_param('si', $googleId, $userId);
    $updateStmt->execute();
    $updateStmt->close();

    $fullname = $existingUser['fullname'];
    $role     = $existingUser['role'];
    $phone    = $existingUser['phone'];
} else {
    // New Google account -> Create user with email_verified = 1 and google_id
    $randomPassword = generate_secure_token(16);
    $hashedPassword = password_hash($randomPassword, PASSWORD_DEFAULT);
    $role           = 'user';
    $phone          = null;

    $insertStmt = $conn->prepare('INSERT INTO users (fullname, email, password, role, email_verified, google_id) VALUES (?, ?, ?, ?, 1, ?)');
    $insertStmt->bind_param('sssss', $googleName, $googleEmail, $hashedPassword, $role, $googleId);
    $insertStmt->execute();
    $userId   = $insertStmt->insert_id;
    $insertStmt->close();

    $fullname = $googleName;
}

// Regenerate session ID (Session Fixation protection)
regenerate_session();


// Populate session identity
$_SESSION['user_id']  = $userId;
$_SESSION['fullname'] = $fullname;
$_SESSION['email']    = $googleEmail;
$_SESSION['phone']    = $phone;
$_SESSION['role']     = $role;

header('Location: dashboard.php');
exit;
