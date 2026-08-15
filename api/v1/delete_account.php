<?php
/**
 * ============================================================================
 *  api/v1/delete_account.php — SECURE REST API V1 ACCOUNT DELETION ENDPOINT
 * ============================================================================
 *  Authentication Required: Session or API Key (`delete_own_account`).
 *  Authorization Required: Ownership check (`can_access_user_resource`).
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

enforce_rate_limit($conn, 'api_v1_delete_account', 5, 60);

$auth = authenticate_api_request($conn, 'delete_own_account');
$method = $_SERVER['REQUEST_METHOD'] ?? 'POST';

if ($method !== 'POST' && $method !== 'DELETE') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed.'], JSON_UNESCAPED_SLASHES);
    exit;
}

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

$requestedId = isset($data['id']) ? (int)$data['id'] : $auth['user_id'];
if (!can_access_user_resource($requestedId)) {
    http_response_code(403);
    echo json_encode(['error' => 'Access Denied: You cannot delete another user\'s account.'], JSON_UNESCAPED_SLASHES);
    exit;
}

// Cannot delete super_admin accounts via API
$stmt = $conn->prepare('SELECT role FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $requestedId);
$stmt->execute();
$roleRow = $stmt->get_result()->fetch_assoc();
$stmt->close();

if ($roleRow && $roleRow['role'] === 'super_admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Security Protection: Super Administrator accounts cannot be deleted.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$delStmt = $conn->prepare('DELETE FROM users WHERE id = ?');
$delStmt->bind_param('i', $requestedId);

if ($delStmt->execute()) {
    $delStmt->close();
    log_security_event('ACCOUNT_DELETED', ['deleted_user_id' => $requestedId], $requestedId, 'WARNING');

    if ($requestedId === (int)($_SESSION['user_id'] ?? 0)) {
        session_unset();
        session_destroy();
    }

    echo json_encode(['success' => true, 'message' => 'Account and associated data deleted successfully.'], JSON_UNESCAPED_SLASHES);
    exit;
} else {
    $delStmt->close();
    http_response_code(500);
    echo json_encode(['error' => 'Failed to delete account.'], JSON_UNESCAPED_SLASHES);
    exit;
}
