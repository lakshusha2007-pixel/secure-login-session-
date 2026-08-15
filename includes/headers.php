<?php
/**
 * ============================================================================
 *  includes/headers.php — HARDENED SECURITY HTTP HEADERS & CSP NONCE GENERATOR
 * ============================================================================
 *  Configures production-grade security headers, HSTS, frame options, and
 *  Content-Security-Policy (CSP) with dynamic per-request cryptographic nonces.
 * ============================================================================
 */

/**
 * Returns a cryptographically-secure per-request CSP nonce.
 */
function get_csp_nonce(): string
{
    static $nonce = null;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(16));
    }
    return $nonce;
}

/**
 * Sends hardened HTTP security headers and CSP policy.
 */
function send_security_headers(bool $isPrivate = true): void
{
    if (headers_sent()) {
        return;
    }

    // Transport & Framing Protection
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()');

    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }

    // Cache Control for Private Authenticated Pages
    if ($isPrivate) {
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
    }

    // Content Security Policy
    $nonce = get_csp_nonce();
    $reportUri = '/api/v1/csp_report.php';
    
    $cspDirectives = [
        "default-src 'self'",
        "script-src 'self' 'nonce-{$nonce}'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "report-uri {$reportUri}"
    ];

    $cspString = implode('; ', $cspDirectives);

    $isReportOnly = filter_var(getenv('CSP_REPORT_ONLY') ?: ($_ENV['CSP_REPORT_ONLY'] ?? false), FILTER_VALIDATE_BOOLEAN);

    if ($isReportOnly) {
        header("Content-Security-Policy-Report-Only: {$cspString}");
    } else {
        header("Content-Security-Policy: {$cspString}");
    }
}
