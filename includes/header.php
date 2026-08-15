<?php
/**
 * ============================================================================
 *  includes/header.php — SHARED HTML HEAD + TOP NAVIGATION + SECURITY HEADERS
 * ============================================================================
 */

// Dispatch hardened security headers and CSP policy with nonce
if (function_exists('send_security_headers')) {
    send_security_headers(true);
}

$pageTitle   = $pageTitle ?? 'Secure Login System';
$assetPrefix = file_exists(__DIR__ . '/../assets/css/style.css') && str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/admin/') ? '../' : '';
$cspNonce    = function_exists('get_csp_nonce') ? get_csp_nonce() : '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo e($pageTitle); ?></title>

    <!-- Google Fonts with Subresource Integrity / CORS attributes -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet" crossorigin="anonymous">

    <!-- Local Application Stylesheet -->
    <link rel="stylesheet" href="<?php echo $assetPrefix; ?>assets/css/style.css">
</head>
<body>

<?php if (function_exists('is_impersonating') && is_impersonating()): ?>
    <!-- Prominent Impersonation Mode Active Top Banner -->
    <div style="background: #fff1f2; border-bottom: 2px solid #e11d48; color: #9f1239; padding: 0.6rem 1rem; font-size: 0.88rem; font-weight: 600; text-align: center; display: flex; justify-content: center; align-items: center; gap: 1rem; flex-wrap: wrap;">
        <span>⚠️ <strong>IMPERSONATION MODE ACTIVE:</strong> Currently acting as User ID #<?php echo e((string)$_SESSION['user_id']); ?> (<?php echo e($_SESSION['fullname'] ?? ''); ?> &lt;<?php echo e($_SESSION['email'] ?? ''); ?>&gt;)</span>
        <a href="<?php echo $assetPrefix; ?>admin/impersonate.php?action=exit" style="background: #e11d48; color: #ffffff; padding: 0.25rem 0.75rem; border-radius: 4px; text-decoration: none; font-size: 0.8rem; font-weight: 700;">Exit Impersonation &rarr;</a>
    </div>
<?php endif; ?>

<header class="site-header">
    <div class="container nav-wrap">
        <!-- Brand / logo -->
        <a class="brand" href="<?php echo $assetPrefix; ?>index.php">
            <span class="brand-badge">&#128274;</span> Secure<span class="text-highlight">Auth</span>
        </a>

        <!-- Navigation links -->
        <nav class="nav">
            <a href="<?php echo $assetPrefix; ?>index.php">Home</a>

            <?php if (is_logged_in()): ?>
                <a href="<?php echo $assetPrefix; ?>dashboard.php">Dashboard</a>
                <a href="<?php echo $assetPrefix; ?>profile.php">Profile</a>

                <?php if (is_admin()): ?>
                    <a href="<?php echo $assetPrefix; ?>admin/index.php" style="color: var(--primary); font-weight: 700;">⚙️ Admin Panel</a>
                    <a href="<?php echo $assetPrefix; ?>admin/logs.php">Audit Logs</a>
                <?php endif; ?>

                <form method="post" action="<?php echo $assetPrefix; ?>logout.php" style="display: inline; margin: 0;">
                    <?php echo csrf_field(); ?>
                    <button type="submit" class="nav-btn" style="border: none; font: inherit; cursor: pointer; line-height: inherit;">Logout</button>
                </form>
            <?php else: ?>
                <a href="<?php echo $assetPrefix; ?>register.php">Register</a>
                <a class="nav-btn" href="<?php echo $assetPrefix; ?>login.php">Login</a>
            <?php endif; ?>
        </nav>
    </div>
</header>

<main class="container">
