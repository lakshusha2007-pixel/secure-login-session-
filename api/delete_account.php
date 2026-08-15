<?php
/**
 * ============================================================================
 *  api/delete_account.php — LEGACY DELETE ENDPOINT (DEPRECATED -> V1 PROXY)
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

send_api_deprecation_headers('/api/v1/delete_account.php', '2027-01-01');

require __DIR__ . '/v1/delete_account.php';
