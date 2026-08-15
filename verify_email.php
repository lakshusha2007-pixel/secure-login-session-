<?php
/**
 * ============================================================================
 *  verify_email.php — EMAIL VERIFICATION TOKEN HANDLER
 * ============================================================================
 *  Validates single-use random verification tokens sent to registered emails.
 *  Activates account (email_verified = 1) and invalidates the token.
 * ============================================================================
 */

require_once __DIR__ . '/includes/auth.php';

$token  = trim($_GET['token'] ?? '');
$status = 'error';
$msg    = '';

if ($token === '') {
    $msg = 'Invalid or missing verification token.';
} else {
    // Lookup user by matching verification token and unexpired time
    $stmt = $conn->prepare('SELECT id, fullname, email, email_verified, verification_expires FROM users WHERE verification_token = ? LIMIT 1');
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $user   = $result->fetch_assoc();
    $stmt->close();

    if (!$user) {
        $msg = 'Invalid or expired verification token.';
    } elseif ((int)$user['email_verified'] === 1) {
        $status = 'success';
        $msg    = 'Your email address is already verified! You can log in to your account.';
    } else {
        $expiresAt = strtotime($user['verification_expires'] ?? '1970-01-01');
        if (time() > $expiresAt) {
            $msg = 'This verification token has expired. Please register again or request a new verification token.';
        } else {
            // SUCCESS: Mark email as verified and clear token
            $updateStmt = $conn->prepare('UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires = NULL WHERE id = ?');
            $updateStmt->bind_param('i', $user['id']);
            if ($updateStmt->execute()) {
                $status = 'success';
                $msg    = 'Your email address has been verified successfully! You may now sign in.';
            } else {
                $msg    = 'Verification failed due to a database error. Please try again.';
            }
            $updateStmt->close();
        }
    }
}

$pageTitle = 'Email Verification — Secure Login System';
require_once __DIR__ . '/includes/header.php';
?>

<div class="card" style="text-align: center;">
    <h2>Email Verification</h2>

    <?php if ($status === 'success'): ?>
        <div class="alert alert-success" style="margin-top: 1.5rem;">
            <?php echo e($msg); ?>
        </div>
        <p style="margin-top: 1.5rem;">
            <a class="btn btn-primary" href="login.php" style="width: 100%;">Sign In to Account &rarr;</a>
        </p>
    <?php else: ?>
        <div class="alert alert-error" style="margin-top: 1.5rem;">
            <?php echo e($msg); ?>
        </div>
        <div style="display: flex; gap: 0.75rem; margin-top: 1.5rem; justify-content: center; flex-wrap: wrap;">
            <a class="btn" href="register.php" style="background: var(--bg-app); border: 1px solid var(--border); color: var(--text-main); text-decoration: none;">Register Account</a>
            <a class="btn btn-primary" href="login.php" style="width: auto;">Sign In</a>
        </div>
    <?php endif; ?>
</div>

<?php require_once __DIR__ . '/includes/footer.php'; ?>
