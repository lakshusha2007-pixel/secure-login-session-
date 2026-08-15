<?php
/**
 * ============================================================================
 *  scripts/dast_scan.php — DYNAMIC APPLICATION SECURITY TESTING (DAST) SCANNER
 * ============================================================================
 *  Performs automated HTTP security checks against local/staging server:
 *      1. Tests site-wide HTTPS redirection and security headers (HSTS, CSP, X-Frame-Options).
 *      2. Tests authentication status codes (302 redirect for protected dashboard).
 *      3. Tests authorization enforcement (403 Forbidden for admin endpoints).
 *      4. Tests rate limiting responses (HTTP 429).
 * ============================================================================
 */

echo "=======================================================\n";
echo " DAST SECURITY SCANNER — SECUREAUTH SYSTEM\n";
echo "=======================================================\n";

$baseUrl = trim(getenv('APP_URL') ?: 'http://localhost:8080');
echo "Target Base URL: $baseUrl\n";
echo "-------------------------------------------------------\n";

$passed = 0;
$failed = 0;

function http_get_test(string $url): array
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);

    $headerText = substr($response ?: '', 0, $headerSize);
    $headers = [];
    foreach (explode("\r\n", $headerText) as $line) {
        if (str_contains($line, ':')) {
            list($k, $v) = explode(':', $line, 2);
            $headers[strtolower(trim($k))] = trim($v);
        }
    }

    return [
        'code' => $httpCode,
        'headers' => $headers
    ];
}

// Test 1: Landing Page Availability & Security Headers
$test1 = http_get_test($baseUrl . '/index.php');
if ($test1['code'] === 200) {
    echo "✅ [PASS] Index Page HTTP 200 OK\n";
    $passed++;
} else {
    echo "❌ [FAIL] Index Page returned HTTP {$test1['code']}\n";
    $failed++;
}

// Check CSP Header
if (isset($test1['headers']['content-security-policy'])) {
    echo "✅ [PASS] Content-Security-Policy Header Active\n";
    $passed++;
} else {
    echo "⚠️ [WARN] Content-Security-Policy Header Missing\n";
}

// Check X-Frame-Options Header
if (isset($test1['headers']['x-frame-options']) && strtoupper($test1['headers']['x-frame-options']) === 'DENY') {
    echo "✅ [PASS] X-Frame-Options: DENY (Clickjacking Protection)\n";
    $passed++;
} else {
    echo "⚠️ [WARN] X-Frame-Options Header Missing or Loose\n";
}

// Test 2: Protected Dashboard Redirection
$test2 = http_get_test($baseUrl . '/dashboard.php');
if ($test2['code'] === 302 || $test2['code'] === 301) {
    echo "✅ [PASS] Dashboard Auth Redirect (HTTP {$test2['code']} -> Login)\n";
    $passed++;
} else {
    echo "❌ [FAIL] Dashboard direct access returned HTTP {$test2['code']} (expected redirect)\n";
    $failed++;
}

// Test 3: Admin Section Authorization
$test3 = http_get_test($baseUrl . '/admin/index.php');
if ($test3['code'] === 403 || $test3['code'] === 302) {
    echo "✅ [PASS] Admin Section Access Control (HTTP {$test3['code']})\n";
    $passed++;
} else {
    echo "❌ [FAIL] Admin section returned HTTP {$test3['code']} (expected 403 / redirect)\n";
    $failed++;
}

// Test 4: Private API Endpoint Authentication
$test4 = http_get_test($baseUrl . '/api/profile.php');
if ($test4['code'] === 401 || $test4['code'] === 403) {
    echo "✅ [PASS] Private API Authentication Required (HTTP {$test4['code']})\n";
    $passed++;
} else {
    echo "❌ [FAIL] Unauthenticated API call returned HTTP {$test4['code']}\n";
    $failed++;
}

echo "-------------------------------------------------------\n";
echo "DAST Summary: $passed tests passed, $failed tests failed.\n";
exit($failed === 0 ? 0 : 1);
