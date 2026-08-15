<?php
/**
 * ============================================================================
 *  audit_logs.php — REAL-TIME SECURITY EVENT AUDIT LOG PANEL
 * ============================================================================
 *
 *  Displays all logged security events recorded by log_security_event():
 *      - Login attempts (successful & failed)
 *      - Lockouts & rate limit activations
 *      - Password changes & rehashing events
 *      - CSRF token violations
 *      - Logout & session terminations
 *
 *  Features:
 *      - Parameterized filtering by severity and event type.
 *      - XSS-safe output encoding.
 *      - Live log view from MySQL database table `security_logs` with fallback
 *        to file log `logs/security.log`.
 *
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Enforce Server-Side Authorization: Admin Role Only
require_admin();

$pageTitle = 'Security Audit Logs — Secure Login System';
require_once __DIR__ . '/includes/header.php';


// Filter parameters
$filterSeverity  = trim($_GET['severity'] ?? '');
$filterEventType = trim($_GET['event_type'] ?? '');

$logs = [];
$dbError = '';

// Query security_logs database table using prepared statement
try {
    $whereClauses = [];
    $params = [];
    $types  = '';

    if ($filterSeverity !== '') {
        $whereClauses[] = 'severity = ?';
        $params[] = $filterSeverity;
        $types   .= 's';
    }

    if ($filterEventType !== '') {
        $whereClauses[] = 'event_type = ?';
        $params[] = $filterEventType;
        $types   .= 's';
    }

    $sql = 'SELECT id, user_id, event_type, ip_address, user_agent, details, severity, created_at FROM security_logs';
    if (!empty($whereClauses)) {
        $sql .= ' WHERE ' . implode(' AND ', $whereClauses);
    }
    $sql .= ' ORDER BY id DESC LIMIT 100';

    $stmt = $conn->prepare($sql);
    if (!empty($params)) {
        $stmt->bind_param($types, ...$params);
    }
    $stmt->execute();
    $res = $stmt->get_result();
    while ($row = $res->fetch_assoc()) {
        $logs[] = $row;
    }
    $stmt->close();
} catch (Throwable $e) {
    $dbError = 'Database audit log query unavailable: ' . $e->getMessage();
}

// Fallback: Read file logs/security.log if DB query is empty and no filters applied
if (empty($logs) && empty($filterSeverity) && empty($filterEventType)) {
    $logFile = __DIR__ . '/logs/security.log';
    if (file_exists($logFile)) {
        $lines = array_reverse(file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
        $lines = array_slice($lines, 0, 50);
        foreach ($lines as $idx => $line) {
            // Parse line format: [timestamp] [SEVERITY] [IP: xxx] [User ID: yyy] Event: ZZZ | Details: {...} | UA: ...
            if (preg_match('/^\[(.*?)\] \[(.*?)\] \[IP: (.*?)\] \[User ID: (.*?)\] Event: (.*?) \| Details: (.*?) \| UA: (.*)$/', $line, $matches)) {
                $logs[] = [
                    'id'         => 'File-' . ($idx + 1),
                    'created_at' => $matches[1],
                    'severity'   => $matches[2],
                    'ip_address' => $matches[3],
                    'user_id'    => $matches[4] !== 'N/A' ? $matches[4] : null,
                    'event_type' => $matches[5],
                    'details'    => $matches[6],
                    'user_agent' => $matches[7],
                ];
            }
        }
    }
}
?>

<div class="card" style="max-width: 1000px; margin: 2rem auto;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
            <h2>&#128737; Security Audit Logs</h2>
            <p class="card-sub" style="margin-bottom: 0;">Real-time security event tracking and incident audit trail.</p>
        </div>
        <div>
            <a href="audit_logs.php" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;">Refresh Logs</a>
        </div>
    </div>

    <!-- Filter Form -->
    <form method="get" action="audit_logs.php" style="display: flex; gap: 1rem; margin-bottom: 1.5rem; background: var(--bg-light); padding: 1rem; border-radius: 8px;">
        <div style="flex: 1;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.25rem;">Filter Severity</label>
            <select name="severity" style="width: 100%; padding: 0.5rem; border-radius: 6px; border: 1px solid var(--border);">
                <option value="">All Severities</option>
                <option value="INFO" <?php echo $filterSeverity === 'INFO' ? 'selected' : ''; ?>>INFO</option>
                <option value="WARNING" <?php echo $filterSeverity === 'WARNING' ? 'selected' : ''; ?>>WARNING</option>
                <option value="ALERT" <?php echo $filterSeverity === 'ALERT' ? 'selected' : ''; ?>>ALERT</option>
                <option value="CRITICAL" <?php echo $filterSeverity === 'CRITICAL' ? 'selected' : ''; ?>>CRITICAL</option>
            </select>
        </div>

        <div style="flex: 1;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.25rem;">Filter Event Type</label>
            <input type="text" name="event_type" value="<?php echo e($filterEventType); ?>" placeholder="e.g. LOGIN_SUCCESS" style="width: 100%; padding: 0.5rem; border-radius: 6px; border: 1px solid var(--border);">
        </div>

        <div style="display: flex; align-items: flex-end;">
            <button type="submit" class="btn btn-primary" style="padding: 0.5rem 1.25rem;">Apply Filters</button>
        </div>
    </form>

    <?php if ($dbError !== ''): ?>
        <div class="alert alert-error"><?php echo e($dbError); ?></div>
    <?php endif; ?>

    <!-- Logs Table -->
    <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.88rem; text-align: left;">
            <thead>
                <tr style="background: var(--bg-light); border-bottom: 2px solid var(--border);">
                    <th style="padding: 0.75rem;">Time</th>
                    <th style="padding: 0.75rem;">Severity</th>
                    <th style="padding: 0.75rem;">Event Type</th>
                    <th style="padding: 0.75rem;">IP Address</th>
                    <th style="padding: 0.75rem;">User ID</th>
                    <th style="padding: 0.75rem;">Context / Details</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($logs)): ?>
                    <tr>
                        <td colspan="6" style="padding: 2rem; text-align: center; color: var(--text-muted);">
                            No security events recorded yet. Perform actions like logging in, registering, or triggering failed attempts to see live events.
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($logs as $log): ?>
                        <?php
                        $sev = strtoupper($log['severity']);
                        $badgeStyle = 'background:#e0f2fe; color:#0369a1;';
                        if ($sev === 'WARNING')  $badgeStyle = 'background:#fef3c7; color:#b45309;';
                        if ($sev === 'ALERT')    $badgeStyle = 'background:#ffedd5; color:#c2410c;';
                        if ($sev === 'CRITICAL') $badgeStyle = 'background:#fee2e2; color:#b91c1c;';
                        ?>
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 0.75rem; white-space: nowrap; font-family: monospace; font-size: 0.8rem;"><?php echo e($log['created_at']); ?></td>
                            <td style="padding: 0.75rem;">
                                <span style="<?php echo $badgeStyle; ?> padding: 0.2rem 0.5rem; border-radius: 99px; font-weight: 700; font-size: 0.75rem; display: inline-block;">
                                    <?php echo e($sev); ?>
                                </span>
                            </td>
                            <td style="padding: 0.75rem; font-weight: 700; color: var(--primary);"><?php echo e($log['event_type']); ?></td>
                            <td style="padding: 0.75rem; font-family: monospace;"><?php echo e($log['ip_address']); ?></td>
                            <td style="padding: 0.75rem;"><?php echo $log['user_id'] ? e($log['user_id']) : '<span style="color:var(--text-muted);">Guest</span>'; ?></td>
                            <td style="padding: 0.75rem; font-family: monospace; font-size: 0.8rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo e($log['details']); ?>">
                                <?php echo e($log['details']); ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
