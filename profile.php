<?php
/**
 * ============================================================================
 *  profile.php — USER PROFILE & ACCOUNT MANAGEMENT
 * ============================================================================
 *  Displays Profile Name, Email, Verification Status badge, and Google Connected status.
 *  Allows logged-in users to update their profile display name securely.
 *  Hides internal IDs, tokens, password hashes, and security metadata.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

// Require user to be logged in
require_login();

$userId     = $_SESSION['user_id'];
$error      = '';
$successMsg = '';

// Fetch current user details from database
$stmt = $conn->prepare('SELECT fullname, email, email_verified, google_id FROM users WHERE id = ? LIMIT 1');
$stmt->bind_param('i', $userId);
$stmt->execute();
$userProfile = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$userProfile) {
    header('Location: logout.php');
    exit;
}

// Handle Profile Name Update Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!verify_csrf($submittedToken)) {
        $error = 'Invalid security token or session expired.';
    } else {
        $newFullname = trim($_POST['fullname'] ?? '');

        if ($newFullname === '') {
            $error = 'Profile name cannot be empty.';
        } elseif (!validate_name_length($newFullname)) {
            $error = 'Profile name must be between 3 and 20 characters long.';
        } else {
            // Prepared SQL Statement: update current authenticated user's name
            $stmt = $conn->prepare('UPDATE users SET fullname = ? WHERE id = ?');
            $stmt->bind_param('si', $newFullname, $userId);

            if ($stmt->execute()) {
                $stmt->close();

                // Update session state and local array
                $_SESSION['fullname'] = $newFullname;
                $userProfile['fullname'] = $newFullname;
                $successMsg = 'Profile name updated successfully!';
            } else {
                $stmt->close();
                $error = 'Failed to update profile name. Please try again.';
            }
        }
    }
}

$pageTitle = 'My Profile — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card">
    <h2>User Profile Settings</h2>
    <p class="card-sub">Manage your account information and display name.</p>

    <?php if ($successMsg !== ''): ?>
        <div class="alert alert-success"><?php echo e($successMsg); ?></div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="alert alert-error"><?php echo e($error); ?></div>
    <?php endif; ?>

    <!-- Profile Status Summary Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.9rem 1rem;">
            <div style="font-size: 0.78rem; text-transform: uppercase; color: #64748b; font-weight: 700; margin-bottom: 0.35rem;">Email Status</div>
            <?php if ((int)$userProfile['email_verified'] === 1): ?>
                <span style="background: #dcfce7; color: #15803d; font-size: 0.82rem; font-weight: 700; padding: 0.25rem 0.65rem; border-radius: 99px; display: inline-block;">&#10004; Verified</span>
            <?php else: ?>
                <span style="background: #fef3c7; color: #b45309; font-size: 0.82rem; font-weight: 700; padding: 0.25rem 0.65rem; border-radius: 99px; display: inline-block;">&#9888; Unverified</span>
            <?php endif; ?>
        </div>

        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 0.9rem 1rem;">
            <div style="font-size: 0.78rem; text-transform: uppercase; color: #64748b; font-weight: 700; margin-bottom: 0.35rem;">Google Account</div>
            <?php if (!empty($userProfile['google_id'])): ?>
                <span style="background: #dbeafe; color: #1d4ed8; font-size: 0.82rem; font-weight: 700; padding: 0.25rem 0.65rem; border-radius: 99px; display: inline-block;">&#10004; Connected</span>
            <?php else: ?>
                <span style="background: #f1f5f9; color: #64748b; font-size: 0.82rem; font-weight: 700; padding: 0.25rem 0.65rem; border-radius: 99px; display: inline-block;">Not Connected</span>
            <?php endif; ?>
        </div>
    </div>

    <form id="profile-form" method="post" action="profile.php" autocomplete="off">
        <?php echo csrf_field(); ?>

        <!-- Email Address -->
        <div class="form-group">
            <label>Registered Email Address</label>
            <input class="form-control" type="text" value="<?php echo e($userProfile['email']); ?>" disabled readonly style="background: #f1f5f9; color: #64748b;">
        </div>

        <!-- Full Name / Username -->
        <div class="form-group">
            <label for="fullname">Profile Display Name <span style="font-weight:normal; color:var(--text-muted);">(3-20 chars)</span></label>
            <input class="form-control" type="text" id="fullname" name="fullname"
                   value="<?php echo e($userProfile['fullname']); ?>"
                   required minlength="3" maxlength="20">
        </div>

        <button type="submit" class="btn btn-primary">&#9998; Save Changes</button>
        <a class="btn nav-btn" href="dashboard.php" style="margin-left: 0.5rem; text-decoration:none;">Back to Dashboard</a>
    </form>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
