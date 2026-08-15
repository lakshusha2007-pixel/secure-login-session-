<?php
/**
 * ============================================================================
 *  includes/error_handler.php — SECURE PRODUCTION ERROR & EXCEPTION HANDLING
 * ============================================================================
 *
 *  Ensures no stack traces, line numbers, or internal server paths are ever
 *  exposed to end users in production mode.
 *
 *  Security Control:
 *      - Suppresses raw error output (`display_errors = 0`).
 *      - Logs full error diagnostics and stack traces to `logs/error.log`.
 *      - Serves generic 500 error page to visitors on unhandled exceptions.
 *
 * ============================================================================
 */

// Production error reporting configuration
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

/**
 * Log error details to server log file
 */
function safe_log_error(string $message, string $file = '', int $line = 0, string $trace = ''): void
{
    $logDir = __DIR__ . '/../logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0750, true);
    }
    $logFile = $logDir . '/error.log';

    $entry = sprintf(
        "[%s] ERROR: %s in %s:%d\nStack trace:\n%s\n----------------------------------------\n",
        date('Y-m-d H:i:s'),
        $message,
        $file,
        $line,
        $trace
    );

    @file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

/**
 * Custom PHP Error Handler
 */
set_error_handler(function (int $errno, string $errstr, string $errfile, int $errline): bool {
    if (!(error_reporting() & $errno)) {
        return false;
    }

    safe_log_error($errstr, $errfile, $errline, debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));

    // Don't execute PHP internal error handler
    return true;
});

/**
 * Custom Uncaught Exception Handler
 */
set_exception_handler(function (Throwable $exception): void {
    safe_log_error(
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        $exception->getTraceAsString()
    );

    // If HTTP headers have not been sent, serve 500 response
    if (!headers_sent()) {
        http_response_code(500);
        if (file_exists(__DIR__ . '/../500.php')) {
            require __DIR__ . '/../500.php';
            exit;
        }
        echo '<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body style="font-family:sans-serif;text-align:center;padding:3rem;"><h2>500 - Internal Server Error</h2><p>An unexpected error occurred. Our engineering team has been notified.</p><a href="index.php">Return to Home</a></body></html>';
    }
    exit;
});
