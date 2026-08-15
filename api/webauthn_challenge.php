<?php
/**
 * ============================================================================
 *  api/webauthn_challenge.php — WEBAUTHN / PASSKEYS CHALLENGE ENDPOINT
 * ============================================================================
 *  Generates a cryptographically secure WebAuthn challenge bound to session
 *  and origin to prevent replay attacks during passkey registration & authentication.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

header('Content-Type: application/json; charset=UTF-8');

// Restricted CORS
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$allowedOrigin = getenv('APP_URL') ?: 'http://localhost:8000';
if ($origin && (strtolower($origin) === strtolower($allowedOrigin) || str_contains($origin, 'localhost'))) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if (!is_logged_in() && empty($_SESSION['mfa_pending'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required for passkey challenges.'], JSON_UNESCAPED_SLASHES);
    exit;
}

// Generate 32-byte random challenge
$challenge = bin2hex(random_bytes(32));
$_SESSION['webauthn_challenge'] = [
    'challenge'  => $challenge,
    'created_at' => time(),
    'user_id'    => $_SESSION['user_id'] ?? ($_SESSION['mfa_pending']['user_id'] ?? 0)
];

$rpId = explode(':', $_SERVER['HTTP_HOST'] ?? 'localhost')[0];

echo json_encode([
    'success'   => true,
    'challenge' => $challenge,
    'rp' => [
        'name' => 'SecureAuth System',
        'id'   => $rpId
    ],
    'user' => [
        'id'          => base64_encode((string)($_SESSION['user_id'] ?? 0)),
        'name'        => $_SESSION['email'] ?? 'user',
        'displayName' => $_SESSION['fullname'] ?? 'User'
    ],
    'pubKeyCredParams' => [
        ['type' => 'public-key', 'alg' => -7],  // ES256
        ['type' => 'public-key', 'alg' => -257] // RS256
    ],
    'timeout' => 60000
], JSON_UNESCAPED_SLASHES);
