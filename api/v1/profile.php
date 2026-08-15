<?php
/**
 * ============================================================================
 *  api/v1/profile.php — SECURE REST API V1 USER PROFILE ENDPOINT
 * ============================================================================
 *  Authentication Required: Session or API Key (`read:profile` / `write:profile`).
 *  Authorization Required: IDOR ownership check (`can_access_user_resource`).
 *  Schema Validation: Validates input fields and schema types.
 *  Rate Limiting: Persistent rate limiting (30 requests/min).
 *  CORS: Restricted origin header matching whitelist.
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

// Enforce persistent rate limiting
enforce_rate_limit($conn, 'api_v1_profile', 30, 60);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Handle GET Profile Request
if ($method === 'GET') {
    $auth = authenticate_api_request($conn, 'read:profile');
    $requestedId = isset($_GET['id']) ? (int)$_GET['id'] : $auth['user_id'];

    if (!can_access_user_resource($requestedId)) {
        http_response_code(403);
        echo json_encode(['error' => 'Access Denied: You do not have permission to view this resource.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $stmt = $conn->prepare('SELECT id, fullname, email, phone, phone_encrypted, role, email_verified, created_at FROM users WHERE id = ? LIMIT 1');
    $stmt->bind_param('i', $requestedId);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) {
        http_response_code(404);
        echo json_encode(['error' => 'User profile not found.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $displayPhone = !empty($user['phone_encrypted']) ? decrypt_pii($user['phone_encrypted']) : ($user['phone'] ?? '');

    echo json_encode([
        'success' => true,
        'user' => [
            'id'             => (int)$user['id'],
            'fullname'       => $user['fullname'],
            'email'          => $user['email'],
            'phone'          => $displayPhone,
            'role'           => $user['role'],
            'email_verified' => (bool)$user['email_verified'],
            'created_at'     => $user['created_at']
        ]
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

// Handle POST/PUT Profile Update Request
if ($method === 'POST' || $method === 'PUT') {
    $auth = authenticate_api_request($conn, 'write:profile');
    $rawInput = file_get_contents('php://input');
    $data     = json_decode($rawInput, true) ?: $_POST;

    // Verify CSRF for session-authenticated web clients
    if ($auth['auth_type'] === 'session') {
        $csrfToken = $data['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        if (!verify_csrf($csrfToken)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid CSRF security token.'], JSON_UNESCAPED_SLASHES);
            exit;
        }
    }

    $requestedId = isset($data['id']) ? (int)$data['id'] : $auth['user_id'];
    if (!can_access_user_resource($requestedId)) {
        http_response_code(403);
        echo json_encode(['error' => 'Access Denied: You cannot modify another user\'s profile.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Input Schema Validation
    $val = validate_input_schema($data, [
        'fullname' => ['required', 'string', 'min_len:3', 'max_len:50'],
        'phone'    => ['string', 'max_len:20']
    ]);

    if (!$val['valid']) {
        send_validation_error($val['errors']);
    }

    $fullname = trim($data['fullname']);
    $phone    = trim($data['phone'] ?? '');

    // Encrypt PII at rest
    $encryptedPhone = encrypt_pii($phone);

    $stmt = $conn->prepare('UPDATE users SET fullname = ?, phone = ?, phone_encrypted = ? WHERE id = ?');
    $stmt->bind_param('sssi', $fullname, $phone, $encryptedPhone, $requestedId);

    if ($stmt->execute()) {
        $stmt->close();
        if ($requestedId === (int)($_SESSION['user_id'] ?? 0)) {
            $_SESSION['fullname'] = $fullname;
        }
        log_security_event('API_PROFILE_UPDATED', ['user_id' => $requestedId], $requestedId, 'INFO');
        echo json_encode(['success' => true, 'message' => 'Profile updated successfully.'], JSON_UNESCAPED_SLASHES);
        exit;
    } else {
        $stmt->close();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update user profile in database.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed.'], JSON_UNESCAPED_SLASHES);
