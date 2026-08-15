<?php
/**
 * ============================================================================
 *  api/v1/siem_export.php — CENTRALIZED SIEM SECURITY LOG EXPORT ENDPOINT
 * ============================================================================
 *  Exports structured JSON security logs for SIEM (Splunk/Elastic) ingestion.
 *  Requires valid API Key authentication.
 * ============================================================================
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../includes/api_auth.php';

// Authenticate via Bearer Token or X-API-KEY header
$authResult = authenticate_api_request($conn, ['read:logs', 'admin']);
if (!$authResult['authenticated']) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized access to SIEM export endpoint.'], JSON_PRETTY_PRINT);
    exit;
}

$limit = isset($_GET['limit']) ? min(1000, max(1, (int)$_GET['limit'])) : 100;
$severity = isset($_GET['severity']) ? trim($_GET['severity']) : null;

$sql = "SELECT id, user_id, event_type, ip_address, user_agent, details, severity, created_at FROM security_logs";
$params = [];
$types = "";

if ($severity) {
    $sql .= " WHERE severity = ?";
    $params[] = $severity;
    $types .= "s";
}

$sql .= " ORDER BY id DESC LIMIT ?";
$params[] = $limit;
$types .= "i";

$stmt = $conn->prepare($sql);
if ($stmt) {
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $res = $stmt->get_result();
    $events = [];
    while ($row = $res->fetch_assoc()) {
        // Decode details if valid JSON
        $details = json_decode($row['details'] ?? '', true);
        $events[] = [
            'event_id' => (int)$row['id'],
            'timestamp' => date('c', strtotime($row['created_at'])),
            'user_id' => $row['user_id'] ? (int)$row['user_id'] : null,
            'event_type' => $row['event_type'],
            'ip_address' => $row['ip_address'],
            'user_agent' => $row['user_agent'],
            'severity' => $row['severity'],
            'details' => $details !== null ? $details : $row['details']
        ];
    }
    $stmt->close();

    echo json_encode([
        'status' => 'success',
        'count' => count($events),
        'events' => $events
    ], JSON_PRETTY_PRINT);
} else {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to query security logs.'], JSON_PRETTY_PRINT);
}
