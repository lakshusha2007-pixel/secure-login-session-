<?php
/**
 * ============================================================================
 *  api/v1/csp_report.php — CONTENT SECURITY POLICY (CSP) VIOLATION RECEIVER
 * ============================================================================
 *  Receives and logs CSP violation reports sent by browsers when script/style/img
 *  policy violations occur, aiding real-time XSS monitoring.
 * ============================================================================
 */

require_once __DIR__ . '/../../includes/auth.php';

// Rate limit CSP reports per IP to prevent spamming
enforce_rate_limit($conn, 'csp_report', 50, 60);

header('Content-Type: application/json; charset=UTF-8');

$rawInput = file_get_contents('php://input');
if (empty($rawInput)) {
    http_response_code(400);
    echo json_encode(['error' => 'Empty CSP report payload.'], JSON_UNESCAPED_SLASHES);
    exit;
}

$data = json_decode($rawInput, true);
$report = $data['csp-report'] ?? ($data['csp_report'] ?? $data);

if (!empty($report)) {
    $blockedUri   = $report['blocked-uri'] ?? ($report['blocked_uri'] ?? 'unknown');
    $violatedDir  = $report['violated-directive'] ?? ($report['violated_directive'] ?? 'unknown');
    $documentUri  = $report['document-uri'] ?? ($report['document_uri'] ?? 'unknown');
    $referrer     = $report['referrer'] ?? '';
    $scriptSample = substr($report['script-sample'] ?? '', 0, 100);

    log_security_event('CSP_VIOLATION', [
        'blocked_uri'        => $blockedUri,
        'violated_directive' => $violatedDir,
        'document_uri'       => $documentUri,
        'script_sample'      => $scriptSample,
        'user_agent'         => $_SERVER['HTTP_USER_AGENT'] ?? ''
    ], $_SESSION['user_id'] ?? null, 'WARNING');

    http_response_code(204); // 204 No Content
    exit;
}

http_response_code(400);
echo json_encode(['error' => 'Invalid CSP report structure.'], JSON_UNESCAPED_SLASHES);
