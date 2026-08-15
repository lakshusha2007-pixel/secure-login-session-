<?php
/**
 * ============================================================================
 *  includes/rate_limit.php — PERSISTENT DATABASE-BACKED RATE LIMITING
 * ============================================================================
 *  Protects authentication, API endpoints, and public forms against brute-force
 *  and abuse using IP and identity rate key tracking.
 * ============================================================================
 */

/**
 * Checks if a key & action pair is currently rate-limited.
 */
function check_rate_limit(mysqli $conn, string $rateKey, string $action, int $maxAttempts = 5, int $decaySeconds = 900): array
{
    $rateKey = strtolower(trim($rateKey));
    $action  = strtolower(trim($action));

    $stmt = $conn->prepare('SELECT id, attempts, lockout_until, TIMESTAMPDIFF(SECOND, NOW(), lockout_until) AS remaining_sec FROM rate_limits WHERE rate_key = ? AND action = ? LIMIT 1');
    if (!$stmt) {
        return ['allowed' => true, 'remaining_seconds' => 0, 'attempts' => 0];
    }

    $stmt->bind_param('ss', $rateKey, $action);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if ($row) {
        $remainingSec = (int)($row['remaining_sec'] ?? 0);
        if ($remainingSec > 0 && (int)$row['attempts'] >= $maxAttempts) {
            return [
                'allowed'           => false,
                'remaining_seconds' => $remainingSec,
                'attempts'          => (int)$row['attempts']
            ];
        }

        // Window expired -> clear old lockout
        if ($remainingSec <= 0 && $row['lockout_until'] !== null) {
            $upd = $conn->prepare('UPDATE rate_limits SET attempts = 0, lockout_until = NULL WHERE id = ?');
            if ($upd) {
                $upd->bind_param('i', $row['id']);
                $upd->execute();
                $upd->close();
            }
        }
    }

    return ['allowed' => true, 'remaining_seconds' => 0, 'attempts' => $row ? (int)$row['attempts'] : 0];
}

/**
 * Increments attempt counter for rate limiting.
 */
function record_rate_limit_attempt(mysqli $conn, string $rateKey, string $action, int $maxAttempts = 5, int $decaySeconds = 900): int
{
    $rateKey = strtolower(trim($rateKey));
    $action  = strtolower(trim($action));

    $stmt = $conn->prepare('SELECT id, attempts, lockout_until, TIMESTAMPDIFF(SECOND, NOW(), lockout_until) AS remaining_sec FROM rate_limits WHERE rate_key = ? AND action = ? LIMIT 1');
    if (!$stmt) {
        return 1;
    }

    $stmt->bind_param('ss', $rateKey, $action);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$row) {
        $ins = $conn->prepare('INSERT INTO rate_limits (rate_key, action, attempts, last_attempt) VALUES (?, ?, 1, NOW())');
        if ($ins) {
            $ins->bind_param('ss', $rateKey, $action);
            $ins->execute();
            $ins->close();
        }
        return 1;
    }

    $remainingSec = (int)($row['remaining_sec'] ?? 0);
    $attempts     = (int)$row['attempts'];

    if ($row['lockout_until'] !== null && $remainingSec <= 0) {
        $attempts = 0;
    }

    $attempts++;

    if ($attempts >= $maxAttempts) {
        $upd = $conn->prepare('UPDATE rate_limits SET attempts = ?, last_attempt = NOW(), lockout_until = DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id = ?');
        if ($upd) {
            $upd->bind_param('iii', $attempts, $decaySeconds, $row['id']);
            $upd->execute();
            $upd->close();
        }
        log_security_event('RATE_LIMIT_EXCEEDED', [
            'rate_key'      => $rateKey,
            'action'        => $action,
            'max_attempts'  => $maxAttempts,
            'decay_seconds' => $decaySeconds
        ], null, 'WARNING');
    } else {
        $upd = $conn->prepare('UPDATE rate_limits SET attempts = ?, last_attempt = NOW() WHERE id = ?');
        if ($upd) {
            $upd->bind_param('ii', $attempts, $row['id']);
            $upd->execute();
            $upd->close();
        }
    }

    return $attempts;
}

/**
 * Resets rate limit counter upon successful action.
 */
function reset_rate_limit(mysqli $conn, string $rateKey, string $action): void
{
    $rateKey = strtolower(trim($rateKey));
    $action  = strtolower(trim($action));

    $stmt = $conn->prepare('DELETE FROM rate_limits WHERE rate_key = ? AND action = ?');
    if ($stmt) {
        $stmt->bind_param('ss', $rateKey, $action);
        $stmt->execute();
        $stmt->close();
    }
}

/**
 * Enforces rate limiting on an endpoint, outputting HTTP 429 if threshold is exceeded.
 */
function enforce_rate_limit(mysqli $conn, string $action, int $maxAttempts = 5, int $decaySeconds = 900): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $key = $ip . ($action !== '' ? ':' . $action : '');

    $check = check_rate_limit($conn, $key, $action, $maxAttempts, $decaySeconds);
    if (!$check['allowed']) {
        http_response_code(429);
        header('Retry-After: ' . $check['remaining_seconds']);
        
        $isJson = (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json')) ||
                  (isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json')) ||
                  str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/api/');

        if ($isJson) {
            header('Content-Type: application/json; charset=UTF-8');
            echo json_encode([
                'error'       => 'Too many requests. Rate limit exceeded.',
                'retry_after' => $check['remaining_seconds']
            ], JSON_UNESCAPED_SLASHES);
        } else {
            echo "<h1>429 Too Many Requests</h1><p>Rate limit exceeded. Please try again in {$check['remaining_seconds']} seconds.</p>";
        }
        exit;
    }
}
