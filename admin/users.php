<?php
/**
 * ============================================================================
 *  admin/users.php — USER & ROLE MANAGEMENT (LEAST-PRIVILEGE ADMIN CONTROL)
 * ============================================================================
 *  Requires login AND `view_users` permission server-side via require_permission().
 *  Allows admins to manage user roles, activation states, and perform audited impersonation.
 *  Least privilege: only super_admin can assign or modify super_admin roles.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

// Enforce Server-Side Authorization: View Users Permission Required
require_permission('view_users');

$error      = $_GET['error'] ?? '';
$successMsg = $_GET['msg'] ?? '';
$currentAdminId = (int)$_SESSION['user_id'];

// Handle Role Assignment or Status Update POST Action
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $action = $_POST['action'] ?? '';
        $targetUserId = (int)($_POST['user_id'] ?? 0);

        if ($targetUserId <= 0) {
            $error = 'Invalid user selected.';
        } elseif ($action === 'update_role') {
            if (!has_permission('edit_users')) {
                $error = 'Access Denied: You lack permission to edit user roles.';
            } else {
                $newRole = strtolower(trim($_POST['role'] ?? 'user'));
                if (!in_array($newRole, ['user', 'admin', 'super_admin'], true)) {
                    $error = 'Invalid role specified.';
                } elseif ($newRole === 'super_admin' && !is_super_admin()) {
                    $error = 'Security Violation: Only Super Administrators can assign the super_admin role.';
                } elseif ($targetUserId === $currentAdminId && $newRole !== get_user_role()) {
                    // Prevent self-demotion
                    $error = 'Security Protection: You cannot modify your own administrative role.';
                } else {
                    // Step-Up Auth requirement for sensitive role change
                    require_step_up(300);

                    $stmt = $conn->prepare('UPDATE users SET role = ? WHERE id = ?');
                    $stmt->bind_param('si', $newRole, $targetUserId);
                    if ($stmt->execute()) {
                        $stmt->close();
                        log_security_event('ADMIN_ROLE_UPDATED', [
                            'target_user_id' => $targetUserId,
                            'new_role'       => $newRole,
                            'updated_by'     => $currentAdminId
                        ], $currentAdminId, 'WARNING');

                        $successMsg = 'User role updated successfully!';
                    } else {
                        $stmt->close();
                        $error = 'Failed to update user role.';
                    }
                }
            }
        } elseif ($action === 'toggle_active') {
            if (!has_permission('disable_users')) {
                $error = 'Access Denied: You lack permission to toggle account activation status.';
            } else {
                $newStatus = (int)($_POST['is_active'] ?? 1);
                if ($targetUserId === $currentAdminId && $newStatus === 0) {
                    $error = 'Security Protection: You cannot deactivate your own administrative account.';
                } else {
                    $stmt = $conn->prepare('UPDATE users SET is_active = ? WHERE id = ?');
                    $stmt->bind_param('ii', $newStatus, $targetUserId);
                    if ($stmt->execute()) {
                        $stmt->close();
                        log_security_event('ADMIN_USER_STATUS_TOGGLED', [
                            'target_user_id' => $targetUserId,
                            'new_is_active'  => $newStatus,
                            'updated_by'     => $currentAdminId
                        ], $currentAdminId, 'WARNING');

                        $successMsg = 'Account status updated successfully!';
                    } else {
                        $stmt->close();
                        $error = 'Failed to update account status.';
                    }
                }
            }
        }
    }
}

// Fetch all registered users from database
$users = [];
try {
    $res = $conn->query('SELECT id, fullname, email, phone, role, email_verified, is_active, created_at FROM users ORDER BY id ASC');
    while ($row = $res->fetch_assoc()) {
        $users[] = $row;
    }
} catch (Throwable $e) {
    $error = 'Failed to load user list: ' . $e->getMessage();
}

$pageTitle = 'User Management — Admin Panel';
require_once __DIR__ . '/../includes/header.php';
?>

<div class="card card-wide">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem;">
        <div>
            <h2>👥 User Directory & Role Assignment</h2>
            <p class="card-sub" style="margin-bottom: 0;">Manage registered accounts, granular RBAC roles, and administrative permissions.</p>
        </div>
        <div>
            <a href="index.php" class="btn btn-secondary" style="font-size: 0.85rem; padding: 0.4rem 0.85rem;">&larr; Admin Overview</a>
        </div>
    </div>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; font-size: 0.88rem; text-align: left;">
            <thead>
                <tr style="background: var(--bg-light); border-bottom: 2px solid var(--border);">
                    <th style="padding: 0.75rem;">ID</th>
                    <th style="padding: 0.75rem;">Full Name</th>
                    <th style="padding: 0.75rem;">Email Address</th>
                    <th style="padding: 0.75rem;">Role</th>
                    <th style="padding: 0.75rem;">Status</th>
                    <th style="padding: 0.75rem;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $u): ?>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 0.75rem; font-weight: 600;">#<?php echo e((string)$u['id']); ?></td>
                        <td style="padding: 0.75rem; font-weight: 600;"><?php echo e($u['fullname']); ?></td>
                        <td style="padding: 0.75rem;"><?php echo e($u['email']); ?></td>
                        <td style="padding: 0.75rem;">
                            <?php if (has_permission('edit_users')): ?>
                                <form method="post" action="users.php" style="display: flex; gap: 0.5rem; align-items: center; margin: 0;">
                                    <?php echo csrf_field(); ?>
                                    <input type="hidden" name="action" value="update_role">
                                    <input type="hidden" name="user_id" value="<?php echo e((string)$u['id']); ?>">
                                    <select name="role" style="padding: 0.25rem 0.5rem; border-radius: 4px; border: 1px solid var(--border); font-size: 0.85rem;">
                                        <option value="user" <?php echo $u['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                                        <option value="admin" <?php echo $u['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                                        <?php if (is_super_admin()): ?>
                                            <option value="super_admin" <?php echo $u['role'] === 'super_admin' ? 'selected' : ''; ?>>Super Admin</option>
                                        <?php endif; ?>
                                    </select>
                                    <button type="submit" class="btn btn-primary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; width: auto;">Save Role</button>
                                </form>
                            <?php else: ?>
                                <span class="status-badge info"><?php echo e(strtoupper($u['role'])); ?></span>
                            <?php endif; ?>
                        </td>
                        <td style="padding: 0.75rem;">
                            <?php if ((int)$u['is_active'] === 1): ?>
                                <span class="status-badge success">Active</span>
                            <?php else: ?>
                                <span class="status-badge warning">Inactive</span>
                            <?php endif; ?>
                        </td>
                        <td style="padding: 0.75rem;">
                            <div style="display: flex; gap: 0.5rem; align-items: center;">
                                <?php if (has_permission('disable_users')): ?>
                                    <form method="post" action="users.php" style="margin: 0;">
                                        <?php echo csrf_field(); ?>
                                        <input type="hidden" name="action" value="toggle_active">
                                        <input type="hidden" name="user_id" value="<?php echo e((string)$u['id']); ?>">
                                        <input type="hidden" name="is_active" value="<?php echo (int)$u['is_active'] === 1 ? '0' : '1'; ?>">
                                        <?php if ((int)$u['is_active'] === 1): ?>
                                            <button type="submit" class="btn btn-danger" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; width: auto;">Deactivate</button>
                                        <?php else: ?>
                                            <button type="submit" class="btn btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; width: auto;">Activate</button>
                                        <?php endif; ?>
                                    </form>
                                <?php endif; ?>

                                <?php if (has_permission('impersonate_users') && (int)$u['id'] !== $currentAdminId && (int)$u['is_active'] === 1 && $u['role'] === 'user'): ?>
                                    <form method="post" action="impersonate.php" style="margin: 0;">
                                        <?php echo csrf_field(); ?>
                                        <input type="hidden" name="action" value="start">
                                        <input type="hidden" name="target_user_id" value="<?php echo e((string)$u['id']); ?>">
                                        <input type="hidden" name="reason" value="Admin Account Audit">
                                        <button type="submit" class="btn btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; width: auto; background: #e0e7ff; color: #3730a3; border-color: #c7d2fe;">👁️ Impersonate</button>
                                    </form>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php require_once __DIR__ . '/../includes/footer.php'; ?>
