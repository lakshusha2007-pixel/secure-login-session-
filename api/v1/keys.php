<?php
/**
 * ============================================================================
 *  api/v1/keys.php — SCOPED & ROTATABLE API KEY MANAGEMENT ENDPOINT
 * ============================================================================
 *  Allows authenticated users to generate, inspect, rotate, and revoke API keys.
 *  Only SHA-256 key hashes are stored in the database; raw keys are returned ONCE.
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

enforce_rate_limit($conn, 'api_v1_keys', 20, 60);

$auth = authenticate_api_request($conn, 'manage_own_keys');
$userId = $auth['user_id'];
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Handle GET: List User's Active & Revoked API Keys
if ($method === 'GET') {
    $stmt = $conn->prepare('SELECT id, key_identifier, name, scopes, last_used_at, expires_at, is_revoked, created_at FROM api_keys WHERE user_id = ? ORDER BY id DESC');
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $res = $stmt->get_result();

    $keys = [];
    while ($row = $res->fetch_assoc()) {
        $keys[] = [
            'id'             => (int)$row['id'],
            'key_identifier' => $row['key_identifier'],
            'name'           => $row['name'],
            'scopes'         => array_map('trim', explode(',', $row['scopes'])),
            'last_used_at'   => $row['last_used_at'],
            'expires_at'     => $row['expires_at'],
            'is_revoked'     => (bool)$row['is_revoked'],
            'created_at'     => $row['created_at']
        ];
    }
    $stmt->close();

    echo json_encode(['success' => true, 'keys' => $keys], JSON_UNESCAPED_SLASHES);
    exit;
}

// Handle POST: Create New API Key
if ($method === 'POST') {
    $rawInput = file_get_contents('php://input');
    $data     = json_decode($rawInput, true) ?: $_POST;

    if ($auth['auth_type'] === 'session') {
        $csrfToken = $data['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        if (!verify_csrf($csrfToken)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid CSRF security token.'], JSON_UNESCAPED_SLASHES);
            exit;
        }
    }

    $val = validate_input_schema($data, [
        'name'   => ['required', 'string', 'min_len:3', 'max_len:60'],
        'scopes' => ['required', 'string']
    ]);

    if (!$val['valid']) {
        send_validation_error($val['errors']);
    }

    $name = trim($data['name']);
    $rawScopes = array_map('trim', explode(',', $data['scopes']));

    $allowedScopes = ['read:profile', 'write:profile', 'export:data'];
    if (is_admin()) {
        $allowedScopes[] = 'read:users';
        $allowedScopes[] = 'read:logs';
    }
    if (is_super_admin()) {
        $allowedScopes[] = 'admin:users';
        $allowedScopes[] = '*';
    }

    $validatedScopes = array_intersect($rawScopes, $allowedScopes);
    if (empty($validatedScopes)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or unauthorized API scopes specified.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Generate Raw Key & Public Identifier
    $identifier = 'sk_live_' . bin2hex(random_bytes(8));
    $secret     = bin2hex(random_bytes(24));
    $rawKey     = $identifier . '.' . $secret;
    $keyHash    = hash('sha256', $rawKey);
    $scopeStr   = implode(',', $validatedScopes);

    // Optional Expiration (Default 1 year)
    $expiresAt = date('Y-m-d H:i:s', strtotime('+1 year'));

    $stmt = $conn->prepare('INSERT INTO api_keys (user_id, key_identifier, key_hash, name, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->bind_param('isssss', $userId, $identifier, $keyHash, $name, $scopeStr, $expiresAt);

    if ($stmt->execute()) {
        $keyId = $stmt->insert_id;
        $stmt->close();

        log_security_event('API_KEY_CREATED', [
            'key_id'         => $keyId,
            'key_identifier' => $identifier,
            'scopes'         => $scopeStr
        ], $userId, 'INFO');

        echo json_encode([
            'success' => true,
            'message' => 'API Key created successfully. Make sure to copy your raw API Key now as it will NOT be shown again.',
            'api_key' => [
                'id'             => $keyId,
                'key_identifier' => $identifier,
                'raw_key'        => $rawKey,
                'name'           => $name,
                'scopes'         => $validatedScopes,
                'expires_at'     => $expiresAt
            ]
        ], JSON_UNESCAPED_SLASHES);
        exit;
    } else {
        $stmt->close();
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create API Key.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

// Handle DELETE: Revoke API Key
if ($method === 'DELETE') {
    $rawInput = file_get_contents('php://input');
    $data     = json_decode($rawInput, true) ?: $_GET;

    $keyId = (int)($data['id'] ?? 0);
    if ($keyId <= 0) {
        http_response_code(400);
        echo json_encode(['error' => 'API Key ID is required.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $stmt = $conn->prepare('UPDATE api_keys SET is_revoked = 1 WHERE id = ? AND user_id = ?');
    $stmt->bind_param('ii', $keyId, $userId);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        $stmt->close();
        log_security_event('API_KEY_REVOKED', ['key_id' => $keyId], $userId, 'WARNING');
        echo json_encode(['success' => true, 'message' => 'API Key revoked successfully.'], JSON_UNESCAPED_SLASHES);
        exit;
    } else {
        $stmt->close();
        http_response_code(404);
        echo json_encode(['error' => 'API Key not found or already revoked.'], JSON_UNESCAPED_SLASHES);
        exit;
    }
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed.'], JSON_UNESCAPED_SLASHES);
