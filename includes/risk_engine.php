<?php
/**
 * ============================================================================
 *  includes/risk_engine.php — CONTINUOUS ACCESS EVALUATION & RISK SCORING
 * ============================================================================
 *  Dynamically evaluates user login and request risk level (LOW, MEDIUM, HIGH, CRITICAL)
 *  based on signals: IP changes, device/user-agent shifts, failed login attempts,
 *  and session age.
 * ============================================================================
 */

require_once __DIR__ . '/logger.php';

function evaluate_request_risk(mysqli $conn, ?int $userId, string $ipAddress, string $userAgent): array
{
    $riskScore = 0;
    $signals = [];

    // Signal 1: Check IP Address anomaly against past 10 logins
    if ($userId !== null && $userId > 0) {
        $stmt = $conn->prepare("SELECT DISTINCT ip_address FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
        if ($stmt) {
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $res = $stmt->get_result();
            $knownIps = [];
            while ($row = $res->fetch_assoc()) {
                $knownIps[] = $row['ip_address'];
            }
            $stmt->close();

            if (!empty($knownIps) && !in_array($ipAddress, $knownIps, true)) {
                $riskScore += 25;
                $signals[] = 'NEW_IP_ADDRESS';
            }
        }
    }

    // Signal 2: Check User Agent / Device anomaly
    if ($userId !== null && $userId > 0) {
        $stmt = $conn->prepare("SELECT DISTINCT user_agent FROM security_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
        if ($stmt) {
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $res = $stmt->get_result();
            $knownUas = [];
            while ($row = $res->fetch_assoc()) {
                $knownUas[] = $row['user_agent'];
            }
            $stmt->close();

            if (!empty($knownUas) && !in_array($userAgent, $knownUas, true)) {
                $riskScore += 20;
                $signals[] = 'DEVICE_USER_AGENT_CHANGE';
            }
        }
    }

    // Signal 3: Check Recent Failed Login Attempts from this IP
    $stmt = $conn->prepare("SELECT COUNT(*) AS failed_count FROM security_logs WHERE ip_address = ? AND event_type = 'LOGIN_FAILED' AND created_at >= NOW() - INTERVAL 15 MINUTE");
    if ($stmt) {
        $stmt->bind_param("s", $ipAddress);
        $stmt->execute();
        $res = $stmt->get_result();
        $failedCount = $res->fetch_assoc()['failed_count'] ?? 0;
        $stmt->close();

        if ($failedCount >= 5) {
            $riskScore += 45;
            $signals[] = 'MULTIPLE_FAILED_LOGINS_HIGH';
        } elseif ($failedCount >= 2) {
            $riskScore += 20;
            $signals[] = 'MULTIPLE_FAILED_LOGINS_MEDIUM';
        }
    }

    // Signal 4: Session age / inactivity check
    if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 86400) {
        $riskScore += 15;
        $signals[] = 'EXTENDED_SESSION_AGE';
    }

    // Determine Risk Level
    $riskLevel = 'LOW';
    if ($riskScore >= 75) {
        $riskLevel = 'CRITICAL';
    } elseif ($riskScore >= 50) {
        $riskLevel = 'HIGH';
    } elseif ($riskScore >= 25) {
        $riskLevel = 'MEDIUM';
    }

    // Record Risk Event in DB if Score > 0
    if ($riskScore > 0) {
        $signalsStr = implode(', ', $signals);
        $stmt = $conn->prepare("INSERT INTO risk_events (user_id, event_type, ip_address, user_agent, risk_score, risk_level, details) VALUES (?, 'RISK_EVALUATION', ?, ?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("ississ", $userId, $ipAddress, $userAgent, $riskScore, $riskLevel, $signalsStr);
            $stmt->execute();
            $stmt->close();
        }

        // Also log in security_logs if HIGH or CRITICAL
        if (in_array($riskLevel, ['HIGH', 'CRITICAL'], true)) {
            log_security_event("RISK_SCORE_{$riskLevel}", [
                'risk_score' => $riskScore,
                'signals' => $signals
            ], $userId, 'WARNING');
        }
    }

    return [
        'score' => $riskScore,
        'level' => $riskLevel,
        'signals' => $signals
    ];
}
