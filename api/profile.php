<?php
/**
 * ============================================================================
 *  api/profile.php — LEGACY PROFILE ENDPOINT (DEPRECATED -> V1 PROXY)
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

// Send API Deprecation Headers
send_api_deprecation_headers('/api/v1/profile.php', '2027-01-01');

// Forward execution to V1 endpoint
require __DIR__ . '/v1/profile.php';
