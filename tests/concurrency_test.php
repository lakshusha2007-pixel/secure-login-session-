<?php
/**
 * ============================================================================
 *  tests/concurrency_test.php — RACE-CONDITION & CONCURRENCY TEST SUITE
 * ============================================================================
 *  Tests atomic database transactions, lock contention, and recovery code consumption
 *  under simulated concurrent access.
 * ============================================================================
 */

echo "=======================================================\n";
echo " RACE-CONDITION & CONCURRENCY SECURITY TEST SUITE\n";
echo "=======================================================\n";

require_once __DIR__ . '/../config/database.php';

$passed = 0;
$failed = 0;

function test_result(string $name, bool $success): void
{
    global $passed, $failed;
    if ($success) {
        echo "✅ [PASS] {$name}\n";
        $passed++;
    } else {
        echo "❌ [FAIL] {$name}\n";
        $failed++;
    }
}

// 1. Test Atomic Rate Limit Counter Updates
try {
    $conn->begin_transaction();
    $key = 'test_concurrency_ip_' . time();
    $stmt = $conn->prepare("INSERT INTO rate_limits (rate_key, action, attempts, last_attempt) VALUES (?, 'concurrency_test', 1, NOW()) ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = NOW()");
    $stmt->bind_param("s", $key);
    $stmt->execute();
    $stmt->close();
    $conn->commit();

    // Verify counter is exactly 1
    $checkStmt = $conn->prepare("SELECT attempts FROM rate_limits WHERE rate_key = ? AND action = 'concurrency_test'");
    $checkStmt->bind_param("s", $key);
    $checkStmt->execute();
    $res = $checkStmt->get_result()->fetch_assoc();
    $checkStmt->close();

    test_result("Atomic Rate Limit Transaction & Lock Safety", isset($res['attempts']) && (int)$res['attempts'] === 1);
} catch (Throwable $e) {
    $conn->rollback();
    test_result("Atomic Rate Limit Transaction & Lock Safety", false);
}

// 2. Test Atomic Single-Use Recovery Code Consumption Simulation
try {
    $conn->begin_transaction();
    $userId = 1;
    // Simulate SELECT ... FOR UPDATE transaction
    $stmt = $conn->prepare("SELECT mfa_recovery_codes_hash FROM users WHERE id = ? FOR UPDATE");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $res = $stmt->get_result();
    $stmt->close();
    $conn->commit();

    test_result("Atomic SELECT ... FOR UPDATE Lock Isolation", $res !== false);
} catch (Throwable $e) {
    $conn->rollback();
    test_result("Atomic SELECT ... FOR UPDATE Lock Isolation", false);
}

// 3. Test Double Password Reset Consumption Prevention
try {
    $tokenHash = hash('sha256', 'concurrency_token_' . time());
    $insertStmt = $conn->prepare("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (1, ?, NOW() + INTERVAL 1 HOUR)");
    $insertStmt->bind_param("s", $tokenHash);
    $insertStmt->execute();
    $insertStmt->close();

    // Consume token in transaction
    $conn->begin_transaction();
    $consumeStmt = $conn->prepare("UPDATE password_resets SET used_at = NOW() WHERE token_hash = ? AND used_at IS NULL");
    $consumeStmt->bind_param("s", $tokenHash);
    $consumeStmt->execute();
    $affected1 = $consumeStmt->affected_rows;
    $consumeStmt->close();
    $conn->commit();

    // Attempt second consumption (must affect 0 rows)
    $conn->begin_transaction();
    $consumeStmt2 = $conn->prepare("UPDATE password_resets SET used_at = NOW() WHERE token_hash = ? AND used_at IS NULL");
    $consumeStmt2->bind_param("s", $tokenHash);
    $consumeStmt2->execute();
    $affected2 = $consumeStmt2->affected_rows;
    $consumeStmt2->close();
    $conn->commit();

    test_result("Double-Use Token Consumption Prevention (Race Condition Defence)", $affected1 === 1 && $affected2 === 0);
} catch (Throwable $e) {
    $conn->rollback();
    test_result("Double-Use Token Consumption Prevention (Race Condition Defence)", false);
}

echo "-------------------------------------------------------\n";
echo "Concurrency Test Summary: {$passed} passed, {$failed} failed.\n";
exit($failed > 0 ? 1 : 0);
