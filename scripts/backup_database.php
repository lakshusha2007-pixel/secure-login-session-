<?php
/**
 * ============================================================================
 *  scripts/backup_database.php — ENCRYPTED DATABASE BACKUP UTILITY
 * ============================================================================
 *  Dumps MySQL database schema and data, encrypting the backup output using
 *  AES-256-CBC. Backups are stored in a protected folder outside public access.
 *  CLI or Admin execution only.
 * ============================================================================
 */

require_once __DIR__ . '/../includes/auth.php';

// Prevent direct unauthenticated web execution
if (php_sapi_name() !== 'cli') {
    require_permission('manage_settings');
    require_step_up(300);
}

$backupDir = __DIR__ . '/backups';
if (!is_dir($backupDir)) {
    mkdir($backupDir, 0750, true);
    file_put_contents($backupDir . '/.htaccess', "Order allow,deny\nDeny from all\n");
}

$tables = ['users', 'api_keys', 'rate_limits', 'password_resets', 'security_logs', 'impersonation_logs', 'user_credentials'];
$sqlDump = "-- SECURE DATABASE BACKUP EXPORT\n";
$sqlDump .= "-- Generated At: " . date('Y-m-d H:i:s') . "\n\n";

foreach ($tables as $tbl) {
    try {
        $res = $conn->query("SHOW CREATE TABLE `{$tbl}`");
        if ($res && $row = $res->fetch_assoc()) {
            $sqlDump .= "DROP TABLE IF EXISTS `{$tbl}`;\n";
            $sqlDump .= $row['Create Table'] . ";\n\n";

            $dataRes = $conn->query("SELECT * FROM `{$tbl}`");
            while ($dataRow = $dataRes->fetch_assoc()) {
                $cols = array_map(function($c) { return "`" . $c . "`"; }, array_keys($dataRow));
                $vals = array_map(function($v) use ($conn) {
                    if ($v === null) return "NULL";
                    return "'" . $conn->real_escape_string($v) . "'";
                }, array_values($dataRow));

                $sqlDump .= "INSERT INTO `{$tbl}` (" . implode(', ', $cols) . ") VALUES (" . implode(', ', $vals) . ");\n";
            }
            $sqlDump .= "\n";
        }
    } catch (Throwable $e) {
        // Table might not exist yet
    }
}

// Encrypt SQL Dump using AES-256-CBC
$passphrase = getenv('APP_ENCRYPTION_KEY') ?: 'SECURE_AUTH_BACKUP_PASSPHRASE_2026';
$key        = hash('sha256', $passphrase, true);
$iv         = random_bytes(16);

$encryptedData = openssl_encrypt($sqlDump, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
$finalPayload  = base64_encode($iv . $encryptedData);

$filename = 'backup_' . date('Y-m-d_His') . '.sql.enc';
$filePath = $backupDir . '/' . $filename;

file_put_contents($filePath, $finalPayload);

log_security_event('DATABASE_BACKUP_CREATED', ['filename' => $filename], $_SESSION['user_id'] ?? null, 'INFO');

if (php_sapi_name() === 'cli') {
    echo "Database backup successfully created and encrypted: {$filename}\n";
} else {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success'  => true,
        'message'  => 'Encrypted database backup generated successfully.',
        'filename' => $filename
    ], JSON_UNESCAPED_SLASHES);
}
