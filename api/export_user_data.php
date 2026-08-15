<?php
/**
 * ============================================================================
 *  api/export_user_data.php — LEGACY EXPORT ENDPOINT (DEPRECATED -> V1 PROXY)
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

send_api_deprecation_headers('/api/v1/export_user_data.php', '2027-01-01');

require __DIR__ . '/v1/export_user_data.php';
