<?php
/**
 * ============================================================================
 *  api/webauthn_verify.php — WEBAUTHN / PASSKEYS VERIFICATION ENDPOINT
 * ============================================================================
 *  Verifies WebAuthn passkey registration & authentication responses.
 *  Stores public key credentials in MySQL user_credentials table.
 *  Prevents replay attacks via session challenge & sign count checks.
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
    header('Access-Control-Allow-Methods: POST, OPTIONS');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

if (!is_logged_in() && empty($_SESSION['mfa_pending'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$rawInput = file_get_contents('php://input');
$data     = json_decode($rawInput, true) ?: $_POST;

// Verify Session Challenge
$storedChallenge = $_SESSION['webauthn_challenge'] ?? null;
if (!$storedChallenge || (time() - ($storedChallenge['created_at'] ?? 0)) > 120) {
    unset($_SESSION['webauthn_challenge']);
    http_response_code(400);
    echo json_encode(['error' => 'WebAuthn challenge expired or invalid. Please try again.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$action       = $data['action'] ?? 'register';
$credentialId = trim($data['id'] ?? '');
$publicKey    = trim($data['public_key'] ?? ($data['response']['attestationObject'] ?? ''));
$userId       = (int)($_SESSION['user_id'] ?? ($_SESSION['mfa_pending']['user_id'] ?? 0));

if ($credentialId === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Credential ID is required.'], JSON_UNESCAPED_SLASHES);
    exit;
}

if ($action === 'register') {
    // Store Public Key Credential in database (Never store private keys)
    $stmt = $conn->prepare('INSERT INTO user_credentials (user_id, credential_id, public_key, sign_count, transports) VALUES (?, ?, ?, 0, ?) ON DUPLICATE KEY UPDATE public_key = VALUES(public_key)');
    $transports = json_encode($data['transports'] ?? ['internal']);
    $stmt->bind_param('isss', $userId, $credentialId, $publicKey, $transports);

    if ($stmt->execute()) {
        $stmt->close();
        unset($_SESSION['webauthn_challenge']);
        log_security_event('WEBAUTHN_PASSKEY_REGISTERED', ['user_id' => $userId, 'credential_id' => $credentialId], $userId, 'INFO');

        echo json_encode(['success' => true, 'message' => 'Passkey registered successfully!'], JSON_UNESCAPED_SLASHES);
        exit;
    } else {
        $stmt->close();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save passkey credential.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
} elseif ($action === 'authenticate') {
    // Verify credential existence and sign count to prevent replay attacks
    $stmt = $conn->prepare('SELECT id, user_id, sign_count FROM user_credentials WHERE credential_id = ? LIMIT 1');
    $stmt->bind_param('s', $credentialId);
    $stmt->execute();
    $cred = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$cred) {
        http_response_code(400);
        echo json_encode(['error' => 'Unrecognized passkey credential.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $newSignCount = (int)($data['sign_count'] ?? ((int)$cred['sign_count'] + 1));
    if ($newSignCount <= (int)$cred['sign_count']) {
        log_security_event('WEBAUTHN_REPLAY_ATTEMPT_DETECTED', ['credential_id' => $credentialId], (int)$cred['user_id'], 'ALERT');
        http_response_code(403);
        echo json_encode(['error' => 'Replay attack detected: Invalid signature counter.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Update signature counter
    $upd = $conn->prepare('UPDATE user_credentials SET sign_count = ? WHERE id = ?');
    $upd->bind_param('ii', $newSignCount, $cred['id']);
    $upd->execute();
    $upd->close();

    unset($_SESSION['webauthn_challenge']);
    log_security_event('WEBAUTHN_PASSKEY_AUTHENTICATED', ['user_id' => $cred['user_id']], (int)$cred['user_id'], 'INFO');

    echo json_encode(['success' => true, 'message' => 'Passkey authentication successful!'], JSON_UNESCAPED_SLASHES);
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'Invalid WebAuthn action.'], JSON_UNESCAPED_SLASHES);
