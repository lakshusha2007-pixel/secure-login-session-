<?php
/**
 * ============================================================================
 *  includes/api_auth.php — REST API AUTHENTICATION, CORS & SCOPED API KEYS
 * ============================================================================
 *  Handles API CORS origin whitelist validation, session & scoped API Key
 *  authentication (`X-API-Key`), scope enforcement, and version deprecation headers.
 * ============================================================================
 */

/**
 * Handles CORS header setting with strict origin whitelisting.
 * NEVER uses wildcard `*` for private APIs.
 */
function handle_api_cors(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (empty($origin)) {
        return;
    }

    $rawAllowed = getenv('ALLOWED_ORIGINS') ?: (getenv('APP_URL') ?: 'http://localhost:8000');
    $allowedOrigins = array_map('trim', explode(',', strtolower($rawAllowed)));
    
    // Add localhost development defaults
    $allowedOrigins[] = 'http://localhost';
    $allowedOrigins[] = 'http://localhost:8000';
    $allowedOrigins[] = 'http://127.0.0.1';
    $allowedOrigins[] = 'http://127.0.0.1:8000';

    $normalizedOrigin = strtolower(trim($origin));
    $isAllowed = in_array($normalizedOrigin, $allowedOrigins, true);

    if (!$isAllowed) {
        // Also allow matching origin domain if running on same host
        $host = $_SERVER['HTTP_HOST'] ?? '';
        if ($host !== '' && (str_contains($normalizedOrigin, strtolower($host)))) {
            $isAllowed = true;
        }
    }

    if ($isAllowed) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-CSRF-Token, Authorization, X-API-Key');
    }

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
}

/**
 * Authenticates API Request via Session OR Scoped API Key (`X-API-Key` / Bearer).
 * Serves HTTP 401 if unauthenticated, HTTP 403 if scope is missing.
 */
function authenticate_api_request(mysqli $conn, ?string $requiredScope = null): array
{
    handle_api_cors();
    header('Content-Type: application/json; charset=UTF-8');

    // 1. Session Authentication Check
    if (is_logged_in()) {
        $userId = (int)$_SESSION['user_id'];
        $role   = get_user_role();

        return [
            'authenticated' => true,
            'auth_type'     => 'session',
            'user_id'       => $userId,
            'role'          => $role,
            'scopes'        => ['*'] // Full session privileges
        ];
    }

    // 2. API Key Header Check (`X-API-Key` or `Authorization: Bearer <key>`)
    $rawApiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
    if (empty($rawApiKey) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
        $authHeader = trim($_SERVER['HTTP_AUTHORIZATION']);
        if (str_starts_with($authHeader, 'Bearer ')) {
            $rawApiKey = trim(substr($authHeader, 7));
        }
    }

    if (empty($rawApiKey)) {
        http_response_code(401);
        echo json_encode([
            'error' => 'Authentication required. Please provide a valid session or API Key.'
        ], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Hash submitted key with SHA-256
    $keyHash = hash('sha256', $rawApiKey);

    $stmt = $conn->prepare('
        SELECT k.id AS key_id, k.user_id, k.scopes, k.expires_at, k.is_revoked, u.role, u.is_active 
        FROM api_keys k
        JOIN users u ON k.user_id = u.id
        WHERE k.key_hash = ? LIMIT 1
    ');
    $stmt->bind_param('s', $keyHash);
    $stmt->execute();
    $keyRecord = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$keyRecord || (int)$keyRecord['is_revoked'] === 1 || (int)$keyRecord['is_active'] === 0) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid or revoked API Key.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    if ($keyRecord['expires_at'] !== null && strtotime($keyRecord['expires_at']) < time()) {
        http_response_code(401);
        echo json_encode(['error' => 'Expired API Key.'], JSON_UNESCAPED_SLASHES);
        exit;
    }

    $scopes = array_map('trim', explode(',', $keyRecord['scopes']));

    // Verify Scope Requirement
    if ($requiredScope !== null && !in_array('*', $scopes, true) && !in_array($requiredScope, $scopes, true)) {
        log_security_event('API_KEY_SCOPE_DENIED', [
            'required_scope' => $requiredScope,
            'key_scopes'     => $keyRecord['scopes'],
            'user_id'        => $keyRecord['user_id']
        ], (int)$keyRecord['user_id'], 'WARNING');

        http_response_code(403);
        echo json_encode(['error' => "Access denied. API Key lacks required scope: '{$requiredScope}'."], JSON_UNESCAPED_SLASHES);
        exit;
    }

    // Update `last_used_at` asynchronously
    $upd = $conn->prepare('UPDATE api_keys SET last_used_at = NOW() WHERE id = ?');
    if ($upd) {
        $upd->bind_param('i', $keyRecord['key_id']);
        $upd->execute();
        $upd->close();
    }

    return [
        'authenticated' => true,
        'auth_type'     => 'api_key',
        'user_id'       => (int)$keyRecord['user_id'],
        'role'          => $keyRecord['role'],
        'scopes'        => $scopes
    ];
}

/**
 * Sends API deprecation and successor migration headers for legacy endpoints.
 */
function send_api_deprecation_headers(string $successorUrl, ?string $sunsetDate = null): void
{
    header('Deprecation: true');
    header('Link: <' . $successorUrl . '>; rel="successor-version"');
    if ($sunsetDate !== null) {
        header('Sunset: ' . $sunsetDate);
    }
}
