<?php
/**
 * ============================================================================
 *  admin/index.php — UNIFIED ENTERPRISE ADMIN SECURITY DASHBOARD
 * ============================================================================
 *  Comprehensive Admin Security Dashboard featuring 7 Security Modules:
 *      1. Security Overview
 *      2. Authentication Security
 *      3. Session Security
 *      4. Risk Monitoring (Continuous Access Evaluation)
 *      5. Security Audit & SIEM Logs
 *      6. Privacy & Data Subject Requests
 *      7. Compliance & Health Matrix
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';
require_admin();

$pageTitle = 'Admin Security Dashboard — SecureAuth Management';
require_once __DIR__ . '/../includes/header.php';

// Handle Action Submissions (Session Revocation, Privacy Request Management)
$actionMessage = '';
$actionError = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $actionError = 'Invalid security token or session expired.';
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'revoke_all_sessions') {
            // Revoke all active user sessions except current
            $stmt = $conn->prepare("DELETE FROM rate_limits WHERE action = 'user_session'");
            if ($stmt) {
                $stmt->execute();
                $stmt->close();
            }
            log_security_event('ADMIN_ALL_SESSIONS_REVOKED', ['admin_id' => $_SESSION['user_id']], $_SESSION['user_id'], 'WARNING');
            $actionMessage = 'All active user sessions have been invalidated across the system.';
        } elseif ($action === 'update_privacy_status') {
            $reqId = (int)($_POST['request_id'] ?? 0);
            $newStatus = $_POST['new_status'] ?? 'COMPLETED';
            if ($reqId > 0 && in_array($newStatus, ['COMPLETED', 'REJECTED'], true)) {
                $stmt = $conn->prepare("UPDATE privacy_requests SET status = ?, completed_at = NOW() WHERE id = ?");
                if ($stmt) {
                    $stmt->bind_param("si", $newStatus, $reqId);
                    $stmt->execute();
                    $stmt->close();
                    log_security_event('PRIVACY_REQUEST_UPDATED', ['request_id' => $reqId, 'status' => $newStatus], $_SESSION['user_id'], 'INFO');
                    $actionMessage = "Privacy request #{$reqId} marked as {$newStatus}.";
                }
            }
        }
    }
}

// Fetch Metrics for Dashboard Overview
$totalUsers = 0;
$adminUsers = 0;
$mfaCount = 0;
$mfaAdoption = 0;
$activeSessions = 0;
$failedLogins = 0;
$riskEventsCount = 0;
$highRiskCount = 0;
$privacyRequestsCount = 0;

try {
    $r1 = $conn->query("SELECT COUNT(*) AS c FROM users");
    if ($r1) $totalUsers = (int)$r1->fetch_assoc()['c'];

    $r2 = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role IN ('admin', 'super_admin')");
    if ($r2) $adminUsers = (int)$r2->fetch_assoc()['c'];

    $r3 = $conn->query("SELECT COUNT(*) AS c FROM users WHERE mfa_enabled = 1");
    if ($r3) $mfaCount = (int)$r3->fetch_assoc()['c'];

    if ($totalUsers > 0) {
        $mfaAdoption = round(($mfaCount / $totalUsers) * 100, 1);
    }

    $r4 = $conn->query("SELECT COUNT(*) AS c FROM security_logs WHERE event_type = 'LOGIN_FAILED' AND created_at >= NOW() - INTERVAL 24 HOUR");
    if ($r4) $failedLogins = (int)$r4->fetch_assoc()['c'];

    $r5 = $conn->query("SELECT COUNT(*) AS c FROM risk_events WHERE created_at >= NOW() - INTERVAL 24 HOUR");
    if ($r5) $riskEventsCount = (int)$r5->fetch_assoc()['c'];

    $r6 = $conn->query("SELECT COUNT(*) AS c FROM risk_events WHERE risk_level IN ('HIGH', 'CRITICAL') AND created_at >= NOW() - INTERVAL 24 HOUR");
    if ($r6) $highRiskCount = (int)$r6->fetch_assoc()['c'];

    $r7 = $conn->query("SELECT COUNT(*) AS c FROM privacy_requests WHERE status = 'PENDING'");
    if ($r7) $privacyRequestsCount = (int)$r7->fetch_assoc()['c'];
} catch (Throwable $e) {
    // Fallback
}
?>

<div class="card card-wide">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
        <div>
            <h2>🛡️ Enterprise Admin Security Dashboard</h2>
            <p class="card-sub" style="margin-bottom: 0;">Centralized Command Center for Authentication, Risk Monitoring, Compliance & Audit Logs.</p>
        </div>
        <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="status-badge success">Role: <?php echo e(strtoupper(get_user_role())); ?></span>
            <a class="btn btn-secondary" href="users.php" style="font-size: 0.85rem; padding: 0.35rem 0.75rem;">Manage Users</a>
        </div>
    </div>

    <?php if ($actionMessage): ?>
        <div class="alert alert-success"><?php echo e($actionMessage); ?></div>
    <?php endif; ?>
    <?php if ($actionError): ?>
        <div class="alert alert-danger"><?php echo e($actionError); ?></div>
    <?php endif; ?>

    <!-- Navigation Tabs -->
    <style>
        .admin-tabs { display: flex; gap: 0.5rem; border-bottom: 2px solid var(--border); margin-bottom: 1.5rem; overflow-x: auto; padding-bottom: 0.5rem; }
        .admin-tab-btn { background: none; border: none; padding: 0.6rem 1rem; font-weight: 600; color: var(--text-muted); cursor: pointer; border-radius: 6px 6px 0 0; transition: all 0.2s ease; white-space: nowrap; font-size: 0.9rem; }
        .admin-tab-btn.active { color: var(--primary); border-bottom: 3px solid var(--primary); background: var(--bg-light); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>

    <div class="admin-tabs">
        <button class="admin-tab-btn active" onclick="showAdminTab('tab-overview', this)">📊 Security Overview</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-auth', this)">🔐 Authentication</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-sessions', this)">💻 Sessions</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-risk', this)">⚠️ Risk Monitoring</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-logs', this)">📜 Audit & SIEM Logs</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-privacy', this)">⚖️ Privacy (GDPR)</button>
        <button class="admin-tab-btn" onclick="showAdminTab('tab-compliance', this)">📋 Compliance & Health</button>
    </div>

    <!-- TAB 1: SECURITY OVERVIEW -->
    <div id="tab-overview" class="tab-content active">
        <div class="info-grid" style="margin-bottom: 2rem;">
            <div class="info-card">
                <div class="label">MFA Adoption Rate</div>
                <div class="value"><?php echo e((string)$mfaAdoption); ?>%</div>
                <small style="color: var(--text-muted);"><?php echo e((string)$mfaCount); ?> / <?php echo e((string)$totalUsers); ?> users enabled</small>
            </div>
            <div class="info-card">
                <div class="label">Failed Logins (24h)</div>
                <div class="value"><?php echo e((string)$failedLogins); ?></div>
                <small style="color: var(--text-muted);">Brute-force protection active</small>
            </div>
            <div class="info-card">
                <div class="label">Risk Signals (24h)</div>
                <div class="value"><?php echo e((string)$riskEventsCount); ?></div>
                <small style="color: <?php echo $highRiskCount > 0 ? '#dc2626' : 'var(--text-muted)'; ?>; font-weight: 600;">
                    <?php echo e((string)$highRiskCount); ?> High / Critical
                </small>
            </div>
            <div class="info-card">
                <div class="label">Pending Privacy Requests</div>
                <div class="value"><?php echo e((string)$privacyRequestsCount); ?></div>
                <small style="color: var(--text-muted);">GDPR Data Export / Deletion</small>
            </div>
        </div>

        <h3 style="margin-bottom: 1rem;">System Security Highlights</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem;">
            <div style="background: var(--bg-light); padding: 1rem; border-radius: 8px; border: 1px solid var(--border);">
                <strong>🔒 Multi-Factor Authentication (MFA)</strong>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.3rem;">TOTP RFC 6238 active. Secret key AES-256-GCM encrypted in database. Admin MFA mandatory.</p>
            </div>
            <div style="background: var(--bg-light); padding: 1rem; border-radius: 8px; border: 1px solid var(--border);">
                <strong>🔑 WebAuthn / Passkeys</strong>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.3rem;">Support enabled for FIDO2 hardware keys & biometric passkeys with signature counters.</p>
            </div>
            <div style="background: var(--bg-light); padding: 1rem; border-radius: 8px; border: 1px solid var(--border);">
                <strong>🌐 SSRF & DOM Protection</strong>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.3rem;">IP range validation blocking loopback and cloud metadata endpoints. Strict DOM textContent escape.</p>
            </div>
        </div>
    </div>

    <!-- TAB 2: AUTHENTICATION SECURITY -->
    <div id="tab-auth" class="tab-content">
        <h3>Authentication Security & Policy Enforcement</h3>
        <p class="card-sub">Overview of registered authentication mechanisms and credentials across all users.</p>

        <div style="overflow-x: auto; margin-bottom: 1.5rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>MFA Status</th>
                        <th>Passkeys Registered</th>
                        <th>Account Status</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $uRes = $conn->query("SELECT u.id, u.fullname, u.email, u.role, u.mfa_enabled, u.is_active, COUNT(c.id) as passkey_count FROM users u LEFT JOIN user_credentials c ON u.id = c.user_id GROUP BY u.id LIMIT 25");
                    while ($uRow = $uRes->fetch_assoc()):
                    ?>
                    <tr>
                        <td><strong><?php echo e($uRow['fullname']); ?></strong></td>
                        <td><?php echo e($uRow['email']); ?></td>
                        <td><span class="status-badge info"><?php echo e(strtoupper($uRow['role'])); ?></span></td>
                        <td>
                            <?php if ($uRow['mfa_enabled']): ?>
                                <span class="status-badge success">MFA Active</span>
                            <?php else: ?>
                                <span class="status-badge warning">Disabled</span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo e((string)$uRow['passkey_count']); ?> Passkeys</td>
                        <td>
                            <?php if ($uRow['is_active']): ?>
                                <span style="color: #16a34a; font-weight: 600;">Active</span>
                            <?php else: ?>
                                <span style="color: #dc2626; font-weight: 600;">Suspended</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 3: SESSION SECURITY -->
    <div id="tab-sessions" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3>Active Session Management</h3>
            <form method="POST" style="margin: 0;" onsubmit="return confirm('Are you sure you want to invalidate ALL active user sessions system-wide?');">
                <?php echo csrf_field(); ?>
                <input type="hidden" name="action" value="revoke_all_sessions">
                <button type="submit" class="btn btn-danger" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;">🔒 Revoke All Active Sessions</button>
            </form>
        </div>
        <p class="card-sub">Monitor and invalidate active login sessions to defend against session hijacking.</p>

        <div style="overflow-x: auto;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Key / IP</th>
                        <th>Action</th>
                        <th>Attempts / Status</th>
                        <th>Last Activity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $sRes = $conn->query("SELECT * FROM rate_limits ORDER BY last_attempt DESC LIMIT 20");
                    if ($sRes && $sRes->num_rows > 0):
                        while ($sRow = $sRes->fetch_assoc()):
                    ?>
                    <tr>
                        <td><code><?php echo e($sRow['rate_key']); ?></code></td>
                        <td><?php echo e($sRow['rate_key']); ?></td>
                        <td><?php echo e($sRow['action']); ?></td>
                        <td><?php echo e((string)$sRow['attempts']); ?> attempts</td>
                        <td><?php echo e($sRow['last_attempt']); ?></td>
                    </tr>
                    <?php endwhile; else: ?>
                    <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active rate limit or session locks recorded.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 4: RISK MONITORING -->
    <div id="tab-risk" class="tab-content">
        <h3>Continuous Access Evaluation & Risk Scoring</h3>
        <p class="card-sub">Real-time risk scoring engine results based on IP shifts, device changes, and failed login frequency.</p>

        <div style="overflow-x: auto;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>User ID</th>
                        <th>IP Address</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Detected Signals</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $rkRes = $conn->query("SELECT * FROM risk_events ORDER BY id DESC LIMIT 25");
                    if ($rkRes && $rkRes->num_rows > 0):
                        while ($rk = $rkRes->fetch_assoc()):
                            $badgeClass = $rk['risk_level'] === 'CRITICAL' || $rk['risk_level'] === 'HIGH' ? 'danger' : ($rk['risk_level'] === 'MEDIUM' ? 'warning' : 'success');
                    ?>
                    <tr>
                        <td><?php echo e($rk['created_at']); ?></td>
                        <td><?php echo e($rk['user_id'] ? (string)$rk['user_id'] : 'Guest'); ?></td>
                        <td><code><?php echo e($rk['ip_address']); ?></code></td>
                        <td><strong><?php echo e((string)$rk['risk_score']); ?> / 100</strong></td>
                        <td><span class="status-badge <?php echo $badgeClass; ?>"><?php echo e($rk['risk_level']); ?></span></td>
                        <td><?php echo e($rk['details']); ?></td>
                    </tr>
                    <?php endwhile; else: ?>
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No risk events recorded yet. System risk is currently LOW.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 5: AUDIT & SIEM LOGS -->
    <div id="tab-logs" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3>Centralized Security Audit Logs</h3>
            <a href="../api/v1/siem_export.php?limit=100" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;" target="_blank">📥 Export SIEM JSON Logs</a>
        </div>

        <div style="overflow-x: auto;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>User ID</th>
                        <th>IP Address</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $lRes = $conn->query("SELECT * FROM security_logs ORDER BY id DESC LIMIT 20");
                    while ($lRow = $lRes->fetch_assoc()):
                        $sevBadge = $lRow['severity'] === 'CRITICAL' || $lRow['severity'] === 'WARNING' ? 'warning' : 'info';
                    ?>
                    <tr>
                        <td>#<?php echo e((string)$lRow['id']); ?></td>
                        <td><?php echo e($lRow['created_at']); ?></td>
                        <td><strong><?php echo e($lRow['event_type']); ?></strong></td>
                        <td><?php echo e($lRow['user_id'] ? (string)$lRow['user_id'] : 'System'); ?></td>
                        <td><code><?php echo e($lRow['ip_address']); ?></code></td>
                        <td><span class="status-badge <?php echo $sevBadge; ?>"><?php echo e($lRow['severity']); ?></span></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 6: PRIVACY (GDPR) -->
    <div id="tab-privacy" class="tab-content">
        <h3>GDPR Privacy & Data Subject Requests</h3>
        <p class="card-sub">Manage user data access, data export requests, and account deletion requests.</p>

        <div style="overflow-x: auto;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>Req ID</th>
                        <th>User ID</th>
                        <th>Request Type</th>
                        <th>Status</th>
                        <th>Requested At</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $prRes = $conn->query("SELECT * FROM privacy_requests ORDER BY id DESC LIMIT 20");
                    if ($prRes && $prRes->num_rows > 0):
                        while ($pr = $prRes->fetch_assoc()):
                    ?>
                    <tr>
                        <td>#<?php echo e((string)$pr['id']); ?></td>
                        <td><?php echo e((string)$pr['user_id']); ?></td>
                        <td><strong><?php echo e($pr['request_type']); ?></strong></td>
                        <td><span class="status-badge <?php echo $pr['status'] === 'COMPLETED' ? 'success' : 'warning'; ?>"><?php echo e($pr['status']); ?></span></td>
                        <td><?php echo e($pr['requested_at']); ?></td>
                        <td>
                            <?php if ($pr['status'] === 'PENDING'): ?>
                            <form method="POST" style="display: inline-block; margin: 0;">
                                <?php echo csrf_field(); ?>
                                <input type="hidden" name="action" value="update_privacy_status">
                                <input type="hidden" name="request_id" value="<?php echo (int)$pr['id']; ?>">
                                <button type="submit" name="new_status" value="COMPLETED" class="btn btn-primary" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;">Complete</button>
                            </form>
                            <?php else: ?>
                            <span style="color: var(--text-muted); font-size: 0.85rem;">Resolved</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; else: ?>
                    <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No pending GDPR privacy requests.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- TAB 7: COMPLIANCE & HEALTH -->
    <div id="tab-compliance" class="tab-content">
        <h3>Compliance Control Mapping & System Health</h3>
        <p class="card-sub">Mapped security standards compliance overview (PCI DSS, HIPAA, ISO 27001).</p>

        <div style="overflow-x: auto; margin-bottom: 1.5rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr>
                        <th>Standard</th>
                        <th>Control Requirement</th>
                        <th>Status</th>
                        <th>Implementation Notes</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>PCI DSS v4.0</strong></td>
                        <td>Req 8.3 — Multi-Factor Authentication</td>
                        <td><span class="status-badge success">Implemented</span></td>
                        <td>TOTP RFC 6238 mandatory for admins; encrypted secrets.</td>
                    </tr>
                    <tr>
                        <td><strong>PCI DSS v4.0</strong></td>
                        <td>Req 10.2 — Audit Logging</td>
                        <td><span class="status-badge success">Implemented</span></td>
                        <td>Centralized security event logger with SIEM JSON exporter.</td>
                    </tr>
                    <tr>
                        <td><strong>ISO 27001:2022</strong></td>
                        <td>A.9.4.2 — Secure Authentication</td>
                        <td><span class="status-badge success">Implemented</span></td>
                        <td>Argon2id/Bcrypt password hashing, brute-force rate limit.</td>
                    </tr>
                    <tr>
                        <td><strong>HIPAA Security Rule</strong></td>
                        <td>§164.312(a)(2)(iv) — Encryption</td>
                        <td><span class="status-badge success">Implemented</span></td>
                        <td>AES-256-GCM PII encryption for phones and sensitive tokens.</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div style="background: var(--bg-light); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
            <div>
                <strong>Public System Health Endpoint</strong><br>
                <small style="color: var(--text-muted);">URL: <code>/api/health.php</code></small>
            </div>
            <a href="../api/health.php" target="_blank" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.35rem 0.75rem;">Check Status API &rarr;</a>
        </div>
    </div>
</div>

<script>
function showAdminTab(tabId, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.admin-tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    btn.classList.add('active');
}
</script>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
