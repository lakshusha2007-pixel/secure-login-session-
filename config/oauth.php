<?php
/**
 * ============================================================================
 *  config/oauth.php — OAUTH 2.0 CONFIGURATION (GOOGLE)
 * ============================================================================
 *  Contains OAuth client credentials & helper functions for Google login.
 *  Placeholders are used so secrets are not hardcoded in source.
 * ============================================================================
 */

require_once __DIR__ . '/env.php';

// --- Google OAuth Credentials (loaded from environment variables) ---
if (!defined('GOOGLE_CLIENT_ID')) {
    define('GOOGLE_CLIENT_ID', getenv('GOOGLE_CLIENT_ID') ?: 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com');
}

if (!defined('GOOGLE_CLIENT_SECRET')) {
    define('GOOGLE_CLIENT_SECRET', getenv('GOOGLE_CLIENT_SECRET') ?: 'YOUR_GOOGLE_CLIENT_SECRET');
}

if (!defined('GOOGLE_REDIRECT_URI')) {
    // Dynamic fallback matching current host (works for localhost and live domains)
    $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = $_SERVER['HTTP_HOST'] ?? 'localhost:8000';
    $defaultRedirect = $protocol . '://' . $host . '/oauth_callback.php';
    define('GOOGLE_REDIRECT_URI', getenv('GOOGLE_REDIRECT_URI') ?: $defaultRedirect);
}

/**
 * Generates Google OAuth 2.0 Authorization URL with CSRF state token
 */
function get_google_auth_url(string $stateToken): string
{
    $params = [
        'client_id'     => GOOGLE_CLIENT_ID,
        'redirect_uri'  => GOOGLE_REDIRECT_URI,
        'response_type' => 'code',
        'scope'         => 'openid email profile',
        'state'         => $stateToken,
        'prompt'        => 'select_account',
    ];

    return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
}

/**
 * Exchanges OAuth authorization code for Google user information
 */
function fetch_google_user_info(string $code): ?array
{
    // If credentials are still placeholders, return simulated profile for local test mode if enabled
    if (GOOGLE_CLIENT_ID === 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com') {
        return null;
    }

    // 1. Exchange code for access token
    $tokenUrl = 'https://oauth2.googleapis.com/token';
    $postData = [
        'code'          => $code,
        'client_id'     => GOOGLE_CLIENT_ID,
        'client_secret' => GOOGLE_CLIENT_SECRET,
        'redirect_uri'  => GOOGLE_REDIRECT_URI,
        'grant_type'    => 'authorization_code',
    ];

    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    $response = curl_exec($ch);
    curl_close($ch);

    if (!$response) {
        return null;
    }

    $tokenData = json_decode($response, true);
    $accessToken = $tokenData['access_token'] ?? null;

    if (!$accessToken) {
        return null;
    }

    // 2. Retrieve user info using access token
    $userInfoUrl = 'https://www.googleapis.com/oauth2/v3/userinfo';
    $ch = curl_init($userInfoUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $accessToken,
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    $userResponse = curl_exec($ch);
    curl_close($ch);

    if (!$userResponse) {
        return null;
    }

    return json_decode($userResponse, true);
}
