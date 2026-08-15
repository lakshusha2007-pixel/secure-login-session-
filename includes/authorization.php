<?php
/**
 * ============================================================================
 *  includes/authorization.php — AUTHORIZATION, RBAC, PERMISSIONS & IMPERSONATION
 * ============================================================================
 *  Enforces server-side authorization:
 *    - Role-Based Access Control (RBAC): user, admin, super_admin
 *    - Granular least-privilege permission matrix
 *    - IDOR Prevention / Object-Level Authorization
 *    - Audited & Logged Administrative Impersonation
 * ============================================================================
 */

if (!defined('ROLE_PERMISSIONS')) {
    define('ROLE_PERMISSIONS', [
        'user' => [
            'view_own_profile',
            'edit_own_profile',
            'manage_own_keys',
            'export_own_data',
            'delete_own_account'
        ],
        'admin' => [
            'view_own_profile',
            'edit_own_profile',
            'manage_own_keys',
            'export_own_data',
            'view_users',
            'edit_users',
            'disable_users',
            'manage_sessions',
            'view_security_logs'
        ],
        'super_admin' => [
            'view_own_profile',
            'edit_own_profile',
            'manage_own_keys',
            'export_own_data',
            'view_users',
            'edit_users',
            'disable_users',
            'manage_sessions',
            'view_security_logs',
            'manage_content',
            'manage_settings',
            'impersonate_users',
            'manage_roles',
            'full_admin'
        ]
    ]);
}

/**
 * Returns the currently active role for the session.
 */
function get_user_role(): string
{
    if (empty($_SESSION['user_id'])) {
        return 'guest';
    }
    return strtolower($_SESSION['role'] ?? 'user');
}

/**
 * Checks if the currently authenticated user possesses a specific role.
 */
function has_role(string $role): bool
{
    if (!is_logged_in()) {
        return false;
    }
    return get_user_role() === strtolower($role);
}

/**
 * Checks if the user possesses any of the given roles.
 */
function has_any_role(array $roles): bool
{
    if (!is_logged_in()) {
        return false;
    }
    $currentRole = get_user_role();
    foreach ($roles as $r) {
        if ($currentRole === strtolower($r)) {
            return true;
        }
    }
    return false;
}

/**
 * Checks if the user is an Admin or Super Admin.
 */
function is_admin(): bool
{
    return has_any_role(['admin', 'super_admin']);
}

/**
 * Checks if the user is a Super Admin.
 */
function is_super_admin(): bool
{
    return has_role('super_admin');
}

/**
 * Enforces server-side role requirement. HTTP 403 on failure.
 */
function require_role(string $role): void
{
    require_login();
    if (!has_role($role)) {
        log_security_event('UNAUTHORIZED_ROLE_ACCESS', [
            'required_role' => $role,
            'user_role'     => get_user_role(),
            'request_uri'   => $_SERVER['REQUEST_URI'] ?? ''
        ], $_SESSION['user_id'] ?? null, 'WARNING');

        http_response_code(403);
        $prefix = (str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/admin/') || str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/api/')) ? '../' : '';
        require_once __DIR__ . '/../' . $prefix . '403.php';
        exit;
    }
}

/**
 * Enforces admin authorization (admin or super_admin).
 */
function require_admin(): void
{
    require_login();
    if (!is_admin()) {
        log_security_event('UNAUTHORIZED_ADMIN_ACCESS', [
            'user_role'   => get_user_role(),
            'request_uri' => $_SERVER['REQUEST_URI'] ?? ''
        ], $_SESSION['user_id'] ?? null, 'WARNING');

        http_response_code(403);
        $prefix = (str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/admin/') || str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/api/')) ? '../' : '';
        require_once __DIR__ . '/../' . $prefix . '403.php';
        exit;
    }
}

/**
 * Enforces Super Admin authorization.
 */
function require_super_admin(): void
{
    require_role('super_admin');
}

/**
 * Granular Permission Check based on least-privilege permission matrix.
 */
function has_permission(string $permission): bool
{
    if (!is_logged_in()) {
        return false;
    }
    $role = get_user_role();
    $perms = ROLE_PERMISSIONS[$role] ?? [];
    return in_array($permission, $perms, true);
}

/**
 * Enforces server-side permission check.
 */
function require_permission(string $permission): void
{
    require_login();
    if (!has_permission($permission)) {
        log_security_event('UNAUTHORIZED_PERMISSION_ACCESS', [
            'required_permission' => $permission,
            'user_role'           => get_user_role(),
            'request_uri'         => $_SERVER['REQUEST_URI'] ?? ''
        ], $_SESSION['user_id'] ?? null, 'WARNING');

        http_response_code(403);
        $prefix = (str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/admin/') || str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/api/')) ? '../' : '';
        require_once __DIR__ . '/../' . $prefix . '403.php';
        exit;
    }
}

/**
 * Object-Level Authorization / IDOR Prevention Helper
 * Checks if current user owns the resource or is an authorized admin.
 */
function can_access_user_resource(int $targetUserId): bool
{
    if (!is_logged_in()) {
        return false;
    }
    if (is_admin()) {
        return true;
    }
    return (int)$_SESSION['user_id'] === $targetUserId;
}

/* ============================================================================
 *  AUDITED USER IMPERSONATION SYSTEM
 * ============================================================================
 */

/**
 * Checks if the current session is running under user impersonation.
 */
function is_impersonating(): bool
{
    return !empty($_SESSION['is_impersonating']) && !empty($_SESSION['impersonator_id']);
}

/**
 * Returns the original Administrator user ID if impersonating.
 */
function get_impersonator_id(): ?int
{
    return is_impersonating() ? (int)$_SESSION['impersonator_id'] : null;
}

/**
 * Initiates an audited user impersonation session.
 * Requires `impersonate_users` permission.
 */
function start_impersonation(mysqli $conn, int $adminId, int $targetUserId, string $reason = 'Admin Investigation'): array
{
    if (!has_permission('impersonate_users')) {
        return ['success' => false, 'message' => 'Access Denied: You lack authorization to impersonate users.'];
    }

    if ($adminId === $targetUserId) {
        return ['success' => false, 'message' => 'You cannot impersonate your own account.'];
    }

    // Fetch target user details
    $stmt = $conn->prepare('SELECT id, fullname, email, role, is_active FROM users WHERE id = ? LIMIT 1');
    $stmt->bind_param('i', $targetUserId);
    $stmt->execute();
    $targetUser = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$targetUser) {
        return ['success' => false, 'message' => 'Target user account not found.'];
    }

    if ((int)$targetUser['is_active'] === 0) {
        return ['success' => false, 'message' => 'Cannot impersonate an inactive account.'];
    }

    // Prevent lower admins from impersonating equal or higher roles unless Super Admin
    if ($targetUser['role'] === 'super_admin' || ($targetUser['role'] === 'admin' && !is_super_admin())) {
        return ['success' => false, 'message' => 'Security Violation: Cannot impersonate administrative accounts of equal or higher level.'];
    }

    // Log impersonation start in database
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $logStmt = $conn->prepare('INSERT INTO impersonation_logs (admin_id, target_user_id, reason, started_at, ip_address) VALUES (?, ?, ?, NOW(), ?)');
    $logStmt->bind_param('iiss', $adminId, $targetUserId, $reason, $ip);
    $logStmt->execute();
    $logId = $logStmt->insert_id;
    $logStmt->close();

    log_security_event('IMPERSONATION_STARTED', [
        'original_admin_id' => $adminId,
        'target_user_id'    => $targetUserId,
        'reason'            => $reason,
        'log_id'            => $logId
    ], $adminId, 'WARNING');

    // Switch session context to target user, preserving original admin context
    $_SESSION['impersonator_id']        = $adminId;
    $_SESSION['impersonator_role']      = $_SESSION['role'];
    $_SESSION['impersonator_name']      = $_SESSION['fullname'];
    $_SESSION['is_impersonating']       = true;
    $_SESSION['impersonation_log_id']   = $logId;

    $_SESSION['user_id']  = (int)$targetUser['id'];
    $_SESSION['email']    = $targetUser['email'];
    $_SESSION['fullname'] = $targetUser['fullname'];
    $_SESSION['role']     = $targetUser['role'];

    regenerate_session();

    return ['success' => true, 'message' => 'Impersonation started successfully.'];
}

/**
 * Terminates active user impersonation and restores Administrator session context.
 */
function stop_impersonation(mysqli $conn): bool
{
    if (!is_impersonating()) {
        return false;
    }

    $adminId     = (int)$_SESSION['impersonator_id'];
    $adminRole   = $_SESSION['impersonator_role'] ?? 'admin';
    $adminName   = $_SESSION['impersonator_name'] ?? 'Admin';
    $targetUserId = (int)$_SESSION['user_id'];
    $logId       = (int)($_SESSION['impersonation_log_id'] ?? 0);

    // Update log record in database
    if ($logId > 0) {
        $upd = $conn->prepare('UPDATE impersonation_logs SET ended_at = NOW() WHERE id = ?');
        if ($upd) {
            $upd->bind_param('i', $logId);
            $upd->execute();
            $upd->close();
        }
    }

    log_security_event('IMPERSONATION_ENDED', [
        'original_admin_id' => $adminId,
        'target_user_id'    => $targetUserId,
        'log_id'            => $logId
    ], $adminId, 'INFO');

    // Fetch original admin email
    $stmt = $conn->prepare('SELECT email FROM users WHERE id = ? LIMIT 1');
    $stmt->bind_param('i', $adminId);
    $stmt->execute();
    $adminRow = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $adminEmail = $adminRow['email'] ?? 'admin@gmail.com';

    // Restore original admin session data
    $_SESSION['user_id']  = $adminId;
    $_SESSION['email']    = $adminEmail;
    $_SESSION['fullname'] = $adminName;
    $_SESSION['role']     = $adminRole;

    unset($_SESSION['impersonator_id']);
    unset($_SESSION['impersonator_role']);
    unset($_SESSION['impersonator_name']);
    unset($_SESSION['is_impersonating']);
    unset($_SESSION['impersonation_log_id']);

    regenerate_session();

    return true;
}
