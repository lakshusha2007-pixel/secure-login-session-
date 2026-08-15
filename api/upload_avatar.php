<?php
/**
 * ============================================================================
 *  api/upload_avatar.php — SECURE FILE UPLOAD HANDLER
 * ============================================================================
 *  Implements Section 1.3 Secure File Upload Controls:
 *      1. Enforces authentication (require_login()) & CSRF protection.
 *      2. Maximum file size check (2 MB limit).
 *      3. Server-side MIME verification using finfo_file() (Never trusts client MIME).
 *      4. Extension allowlist (jpg, jpeg, png, webp).
 *      5. Rejects executable scripts (.php, .phtml, .exe, .sh) & double-extension attacks.
 *      6. Generates randomized cryptographic filename (bin2hex(random_bytes(16))).
 *      7. Stores file in protected uploads/ directory.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

require_login();

$userId = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Location: ../profile.php');
    exit;
}

$submittedToken = $_POST['csrf_token'] ?? '';
if (!verify_csrf($submittedToken)) {
    $_SESSION['flash_error'] = 'Invalid CSRF security token or session expired.';
    header('Location: ../profile.php');
    exit;
}

if (!isset($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
    $_SESSION['flash_error'] = 'No valid file was uploaded or file upload error occurred.';
    header('Location: ../profile.php');
    exit;
}

$file = $_FILES['avatar'];

// 1. Max File Size Check (2 MB limit)
$maxSizeBytes = 2 * 1024 * 1024;
if ($file['size'] > $maxSizeBytes) {
    log_security_event('FILE_UPLOAD_REJECTED', ['reason' => 'size_exceeded', 'size' => $file['size']], $userId, 'WARNING');
    $_SESSION['flash_error'] = 'File size exceeds maximum allowed limit (2 MB).';
    header('Location: ../profile.php');
    exit;
}

// 2. Extension Allowlist Check & Double-Extension Attack Prevention
$originalName = basename($file['name']);
$filenameParts = explode('.', $originalName);
if (count($filenameParts) > 2) {
    // Rejects double extension attacks like "avatar.php.jpg"
    log_security_event('FILE_UPLOAD_REJECTED', ['reason' => 'double_extension', 'name' => $originalName], $userId, 'ALERT');
    $_SESSION['flash_error'] = 'Invalid filename: Double file extensions are strictly prohibited.';
    header('Location: ../profile.php');
    exit;
}

$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
$allowedExtensions = ['jpg', 'jpeg', 'png', 'webp'];
if (!in_array($ext, $allowedExtensions, true)) {
    log_security_event('FILE_UPLOAD_REJECTED', ['reason' => 'disallowed_extension', 'ext' => $ext], $userId, 'WARNING');
    $_SESSION['flash_error'] = 'Disallowed file extension. Allowed formats: JPG, JPEG, PNG, WEBP.';
    header('Location: ../profile.php');
    exit;
}

// 3. Server-Side MIME Verification using finfo_file (Never trust $_FILES['type'])
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

$allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];
if (!in_array($mimeType, $allowedMimeTypes, true)) {
    log_security_event('FILE_UPLOAD_REJECTED', ['reason' => 'mime_mismatch', 'detected_mime' => $mimeType], $userId, 'ALERT');
    $_SESSION['flash_error'] = 'Security Check Failed: File content MIME type mismatch (' . e($mimeType) . ').';
    header('Location: ../profile.php');
    exit;
}

// 4. Generate Randomized Cryptographic Filename
$randomFilename = bin2hex(random_bytes(16)) . '.' . $ext;
$uploadDir = __DIR__ . '/../uploads/';

if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0750, true);
}

$targetFilePath = $uploadDir . $randomFilename;

// Move file to protected uploads/ directory
if (move_uploaded_file($file['tmp_name'], $targetFilePath)) {
    @chmod($targetFilePath, 0640);
    $relativeAvatarPath = 'uploads/' . $randomFilename;

    // Update avatar path in database
    $upd = $conn->prepare('UPDATE users SET avatar = ? WHERE id = ?');
    $upd->bind_param('si', $relativeAvatarPath, $userId);
    $upd->execute();
    $upd->close();

    log_security_event('AVATAR_UPLOADED_SUCCESS', ['user_id' => $userId, 'filename' => $randomFilename], $userId, 'INFO');
    $_SESSION['flash_success'] = 'Profile avatar uploaded successfully!';
} else {
    log_security_event('FILE_UPLOAD_FAILED', ['reason' => 'move_error'], $userId, 'CRITICAL');
    $_SESSION['flash_error'] = 'Failed to save uploaded file. Please try again.';
}

header('Location: ../profile.php');
exit;
