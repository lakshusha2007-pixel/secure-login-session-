<?php
/**
 * ============================================================================
 *  config/env.php — LIGHTWEIGHT ENVIRONMENT VARIABLE LOADER
 * ============================================================================
 *  Loads configuration settings from .env file into $_ENV and getenv().
 * ============================================================================
 */

function load_env_file(string $envPath): void
{
    if (!file_exists($envPath)) {
        return;
    }

    $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        if (str_contains($line, '=')) {
            list($name, $value) = explode('=', $line, 2);
            $name  = trim($name);
            $value = trim($value);

            // Strip surrounding quotes if present
            if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                $value = substr($value, 1, -1);
            }

            if (!empty($name)) {
                putenv("$name=$value");
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }
}

// Auto-load .env file from project root
load_env_file(__DIR__ . '/../.env');

// Fallback: Check config/db_config.php if .env is missing or hidden by FTP
if (!getenv('DB_HOST') && file_exists(__DIR__ . '/db_config.php')) {
    $extraConfig = require __DIR__ . '/db_config.php';
    if (is_array($extraConfig)) {
        foreach ($extraConfig as $k => $v) {
            if (getenv($k) === false) {
                putenv("$k=$v");
                $_ENV[$k] = (string)$v;
                $_SERVER[$k] = (string)$v;
            }
        }
    }
}
