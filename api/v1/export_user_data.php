<?php
/**
 * ============================================================================
 *  api/v1/export_user_data.php — SECURE REST API V1 GDPR USER DATA EXPORT
 * ============================================================================
 *  Authentication Required: Session or API Key (`export:data`).
 *  Authorization Required: IDOR ownership check (`can_access_user_resource`).
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

enforce_rate_limit($conn, 'api_v1_export', 5, 60);

$auth = authenticate_api_request($conn, 'export:data');

$requestedId = isset($_GET['id']) ? (int)$_GET['id'] : $auth['user_id'];
if (!can_access_user_resource($requestedId)) {
    http_response_code(403);
    echo json_encode(['error' => 'Access Denied.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$stmt = $conn->prepare('SELECT id, fullname, email, phone, phone_encrypted, role, email_verified, created_at FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $requestedId);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$user) {
    http_response_code(404);
    echo json_encode(['error' => 'User not found.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$displayPhone = !empty($user['phone_encrypted']) ? decrypt_pii($user['phone_encrypted']) : ($user['phone'] ?? '');

$logStmt = $conn->prepare('SELECT event_type, ip_address, severity, created_at FROM security_logs WHERE user_id = ? ORDER BY id DESC LIMIT 50');
$logStmt->bind_param('i', $requestedId);
$logStmt->execute();
$logsRes = $logStmt->get_result();
$logs = [];
while ($l = $logsRes->fetch_assoc()) {
    $logs[] = $l;
}
$logStmt->close();

log_security_event('GDPR_DATA_EXPORTED', ['user_id' => $requestedId], $requestedId, 'INFO');

header('Content-Type: application/json; charset=UTF-8');
header('Content-Disposition: attachment; filename="user_export_' . $requestedId . '.json"');

echo json_encode([
    'export_metadata' => [
        'generated_at' => date('Y-m-d H:i:s'),
        'system'       => 'SecureAuth v2.0'
    ],
    'account' => [
        'id'             => (int)$user['id'],
        'fullname'       => $user['fullname'],
        'email'          => $user['email'],
        'phone'          => $displayPhone,
        'role'           => $user['role'],
        'email_verified' => (bool)$user['email_verified'],
        'created_at'     => $user['created_at']
    ],
    'security_logs' => $logs
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
