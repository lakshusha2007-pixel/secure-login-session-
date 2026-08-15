<?php
/**
 * ============================================================================
 *  api/v1/logs.php — SECURE REST API V1 SECURITY AUDIT LOGS ENDPOINT
 * ============================================================================
 *  Authentication Required: Session (admin/super_admin) or API Key (`read:logs`).
 *  Authorization Required: `view_security_logs` permission.
 *  Rate Limiting: Persistent rate limiting (30 requests/min).
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

enforce_rate_limit($conn, 'api_v1_logs', 30, 60);

$auth = authenticate_api_request($conn, 'read:logs');

if (!has_permission('view_security_logs')) {
    http_response_code(403);
    echo json_encode(['error' => 'Access Denied: You lack permission to view security audit logs.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$limit = isset($_GET['limit']) ? min((int)$_GET['limit'], 100) : 50;
$offset = isset($_GET['offset']) ? max((int)$_GET['offset'], 0) : 0;

$stmt = $conn->prepare('SELECT id, user_id, event_type, ip_address, severity, details, created_at FROM security_logs ORDER BY id DESC LIMIT ? OFFSET ?');
$stmt->bind_param('ii', $limit, $offset);
$stmt->execute();
$res = $stmt->get_result();

$logs = [];
while ($row = $res->fetch_assoc()) {
    $logs[] = [
        'id'          => (int)$row['id'],
        'user_id'     => $row['user_id'] ? (int)$row['user_id'] : null,
        'event_type'  => $row['event_type'],
        'ip_address'  => $row['ip_address'],
        'severity'    => $row['severity'],
        'details'     => json_decode($row['details'] ?? '{}', true) ?: $row['details'],
        'created_at'  => $row['created_at']
    ];
}
$stmt->close();

echo json_encode([
    'success' => true,
    'count'   => count($logs),
    'logs'    => $logs
], JSON_UNESCAPED_SLASHES);
