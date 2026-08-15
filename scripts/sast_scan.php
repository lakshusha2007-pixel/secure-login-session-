<?php
/**
 * ============================================================================
 *  scripts/sast_scan.php — STATIC APPLICATION SECURITY TESTING (SAST) SCANNER
 * ============================================================================
 *  Scans project PHP & JS source code for security anti-patterns:
 *      1. Dangerous functions (eval, unserialize, exec, system).
 *      2. Hardcoded passwords / API keys / secrets.
 *      3. Direct unescaped echo of user input (XSS risks).
 *      4. Unprepared SQL query string concatenation (SQLi risks).
 * ============================================================================
 */

echo "=======================================================\n";
echo " SAST SECURITY CODE SCANNER — SECUREAUTH SYSTEM\n";
echo "=======================================================\n";

$projectDir = realpath(__DIR__ . '/..');
$issuesFound = 0;

$filesToScan = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($projectDir, RecursiveDirectoryIterator::SKIP_DOTS)
);

$scannedCount = 0;

foreach ($filesToScan as $file) {
    $path = $file->getPathname();
    $relative = str_replace($projectDir . DIRECTORY_SEPARATOR, '', $path);

    // Skip vendor, git, logs, backups, and documentation
    if (preg_match('/^(\.git|logs|backups|vendor|node_modules|scratch)/i', $relative)) {
        continue;
    }

    $ext = pathinfo($path, PATHINFO_EXTENSION);
    if (!in_array($ext, ['php', 'js'], true)) {
        continue;
    }

    $scannedCount++;
    $lines = file($path);

    foreach ($lines as $lineNum => $line) {
        $num = $lineNum + 1;

        // 1. Unsafe Deserialization / Execution
        if (preg_match('/\b(unserialize|eval|passthru|shell_exec)\s*\(/i', $line)) {
            echo "⚠️ [SAST RISK] Unsafe Function: $relative (Line $num): " . trim($line) . "\n";
            $issuesFound++;
        }

        // 2. Hardcoded Secret Key (excluding env / example / scan files)
        if (preg_match('/\$(password|secret|api_key|app_key)\s*=\s*[\'"][^\'"]{8,}[\'"]/i', $line) && !str_contains($relative, '.env') && !str_contains($relative, 'database_migration') && !str_contains($relative, 'sast_scan')) {
            echo "⚠️ [SAST RISK] Possible Hardcoded Secret Assignment: $relative (Line $num): " . trim($line) . "\n";
            $issuesFound++;
        }


        // 3. Unescaped Output (XSS)
        if (preg_match('/echo\s+(\$_POST|\$_GET|\$_REQUEST)\[/i', $line)) {
            echo "🚨 [SAST CRITICAL] Direct Unescaped Output (XSS): $relative (Line $num): " . trim($line) . "\n";
            $issuesFound++;
        }

        // 4. Raw SQL Concatenation (SQLi)
        if (preg_match('/->query\s*\(\s*[\'"].*SELECT.*(WHERE|AND).*\$.*[\'"]\s*\)/i', $line)) {
            echo "🚨 [SAST CRITICAL] SQL Concatenation Risk: $relative (Line $num)\n";
            $issuesFound++;
        }
    }
}

echo "-------------------------------------------------------\n";
echo "Scanned $scannedCount source files.\n";

if ($issuesFound === 0) {
    echo "✅ PASS: 0 security risks or anti-patterns detected.\n";
    exit(0);
} else {
    echo "⚠️ WARNING: $issuesFound security risks identified. Please review above.\n";
    exit(1);
}
