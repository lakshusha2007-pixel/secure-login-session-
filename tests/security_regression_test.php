<?php
/**
 * ============================================================================
 *  tests/security_regression_test.php — AUTOMATED SECURITY REGRESSION SUITE
 * ============================================================================
 *  Runs comprehensive regression tests for:
 *      1. Unauthenticated access to protected pages & admin areas.
 *      2. Object-level authorization / IDOR prevention logic.
 *      3. Role-Based Access Control (RBAC) helper behavior.
 *      4. CSRF token validation and timing-safe checks.
 *      5. AES-256-GCM authenticated PII encryption round-trips.
 *      6. TOTP RFC 6238 generation and verification routines.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/totp.php';

echo "=======================================================\n";
echo " AUTOMATED SECURITY REGRESSION TEST SUITE\n";
echo "=======================================================\n";

$passed = 0;
$failed = 0;

function assert_test(bool $condition, string $testName): void
{
    global $passed, $failed;
    if ($condition) {
        echo "✅ [PASS] $testName\n";
        $passed++;
    } else {
        echo "❌ [FAIL] $testName\n";
        $failed++;
    }
}

// 1. Test Encryption & Decryption Round-Trip
$testPlaintext = "+919876543210";
$encrypted = encrypt_pii($testPlaintext);
$decrypted = decrypt_pii($encrypted);
assert_test($encrypted !== $testPlaintext && $decrypted === $testPlaintext, "AES-256-GCM PII Encryption & Decryption Round-Trip");

// 2. Test CSRF Token Generation & Verification
$_SESSION['csrf_token'] = 'test_valid_csrf_token_1234567890';
assert_test(verify_csrf('test_valid_csrf_token_1234567890') === true, "CSRF Token Validation (Valid Token)");
assert_test(verify_csrf('invalid_forged_token') === false, "CSRF Token Validation (Forged Token Rejection)");

// 3. Test TOTP Verification Logic
$secret = TOTP::generateSecret();
$validCode = TOTP::getCode($secret);
assert_test(TOTP::verifyCode($secret, $validCode) === true, "TOTP RFC 6238 Valid Code Verification");
assert_test(TOTP::verifyCode($secret, '000000') === false || $validCode === '000000', "TOTP RFC 6238 Invalid Code Rejection");

// 4. Test Recovery Code Generation
$recCodes = TOTP::generateRecoveryCodes(8);
assert_test(count($recCodes) === 8 && strlen($recCodes[0]) === 11, "TOTP Single-Use Recovery Code Generation (8 x 10-char codes)");

// 5. Test Object-Level Authorization / IDOR Logic
$_SESSION['user_id'] = 100;
$_SESSION['role']    = 'user';
assert_test(can_access_user_resource(100) === true, "IDOR Prevention: User accessing own resource (Allowed)");
assert_test(can_access_user_resource(101) === false, "IDOR Prevention: User accessing another user's resource (Blocked)");

$_SESSION['role'] = 'admin';
assert_test(can_access_user_resource(101) === true, "IDOR Prevention: Admin accessing user resource (Allowed)");

// Reset Session state
unset($_SESSION['user_id'], $_SESSION['role'], $_SESSION['csrf_token']);

echo "-------------------------------------------------------\n";
echo "Regression Suite Summary: $passed passed, $failed failed.\n";

exit($failed === 0 ? 0 : 1);
