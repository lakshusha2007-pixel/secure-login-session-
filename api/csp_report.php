<?php
/**
 * ============================================================================
 *  api/csp_report.php — LEGACY CSP REPORT ENDPOINT (DEPRECATED -> V1 PROXY)
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

send_api_deprecation_headers('/api/v1/csp_report.php', '2027-01-01');

require __DIR__ . '/v1/csp_report.php';
