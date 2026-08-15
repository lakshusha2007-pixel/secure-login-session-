<?php
/**
 * ============================================================================
 *  api/health.php — PUBLIC-SAFE HEALTH & UPTIME ENDPOINT
 * ============================================================================
 *  Returns a public-safe status response indicating system operational health.
 *  Exposes NO sensitive database credentials, environment variables, or internal paths.
 * ============================================================================
 */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, no-store, must-revalidate');

require_once __DIR__ . '/../config/database.php';

$healthy = true;

try {
    global $conn;
    if (!$conn || $conn->connect_error) {
        $healthy = false;
    } else {
        $res = $conn->query("SELECT 1");
        if (!$res) {
            $healthy = false;
        }
    }
} catch (Throwable $e) {
    $healthy = false;
}

if ($healthy) {
    http_response_code(200);
    echo json_encode([
        'status' => 'healthy',
        'timestamp' => date('c'),
        'service' => 'SecureAuth Web Application'
    ], JSON_PRETTY_PRINT);
} else {
    http_response_code(503);
    echo json_encode([
        'status' => 'unhealthy',
        'timestamp' => date('c'),
        'service' => 'SecureAuth Web Application'
    ], JSON_PRETTY_PRINT);
}
