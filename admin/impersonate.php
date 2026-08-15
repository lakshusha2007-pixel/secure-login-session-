<?php
/**
 * ============================================================================
 *  admin/impersonate.php — AUDITED USER IMPERSONATION CONTROLLER
 * ============================================================================
 *  Requires login AND `impersonate_users` permission server-side.
 *  Handles initiating and exiting impersonation sessions cleanly with audit logging.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

// If exiting impersonation, caller might be operating in target user context
$action = $_GET['action'] ?? ($_POST['action'] ?? '');

if ($action === 'exit') {
    if (!is_impersonating()) {
        header('Location: ../dashboard.php');
        exit;
    }

    stop_impersonation($conn);
    header('Location: users.php?msg=' . urlencode('Impersonation session ended. Admin privileges restored.'));
    exit;
}

// Initiating impersonation requires explicit `impersonate_users` permission
require_permission('impersonate_users');

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'start') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $targetUserId = (int)($_POST['target_user_id'] ?? 0);
        $reason       = trim($_POST['reason'] ?? 'Admin Maintenance & Investigation');
        $adminId      = (int)$_SESSION['user_id'];

        if ($targetUserId <= 0) {
            $error = 'Invalid target user selected.';
        } else {
            $res = start_impersonation($conn, $adminId, $targetUserId, $reason);
            if ($res['success']) {
                header('Location: ../dashboard.php?msg=' . urlencode($res['message']));
                exit;
            } else {
                $error = $res['message'];
            }
        }
    }
}

// Redirect back to user directory on direct GET load
header('Location: users.php' . ($error !== '' ? '?error=' . urlencode($error) : ''));
exit;
