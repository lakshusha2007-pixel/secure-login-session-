<?php
/**
 * ============================================================================
 *  includes/ssrf_protection.php — SSRF (SERVER-SIDE REQUEST FORGERY) PROTECTION
 * ============================================================================
 *  Provides secure URL validation to prevent SSRF vulnerabilities:
 *      1. Validates scheme (HTTP/HTTPS only).
 *      2. Blocks localhost, 127.0.0.1, ::1.
 *      3. Blocks RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
 *      4. Blocks Link-Local / AWS / GCP / Azure metadata endpoints (169.254.169.254).
 *      5. Performs safe DNS resolution and validates resolved IP addresses.
 * ============================================================================
 */

function is_ip_private(string $ip): bool
{
    $flags = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
    return filter_var($ip, FILTER_VALIDATE_IP, $flags) === false;
}

function validate_url_ssrf(string $url, array $allowedDomains = []): array
{
    $parsed = parse_url($url);
    if (!$parsed || empty($parsed['host']) || empty($parsed['scheme'])) {
        return ['valid' => false, 'reason' => 'Invalid or malformed URL structure.'];
    }

    $scheme = strtolower($parsed['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) {
        return ['valid' => false, 'reason' => 'Only HTTP and HTTPS schemes are permitted.'];
    }

    $host = strtolower($parsed['host']);

    // Block obvious local/internal hostnames
    if (in_array($host, ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true) || str_ends_with($host, '.local') || str_ends_with($host, '.internal')) {
        return ['valid' => false, 'reason' => 'Access to internal or loopback hostnames is prohibited.'];
    }

    // Check domain allowlist if specified
    if (!empty($allowedDomains)) {
        $domainAllowed = false;
        foreach ($allowedDomains as $domain) {
            if ($host === strtolower($domain) || str_ends_with($host, '.' . strtolower($domain))) {
                $domainAllowed = true;
                break;
            }
        }
        if (!$domainAllowed) {
            return ['valid' => false, 'reason' => 'Host is not in the allowed domain list.'];
        }
    }

    // Resolve DNS safely
    $ips = gethostbynamel($host);
    if (!$ips) {
        return ['valid' => false, 'reason' => 'DNS resolution failed for host.'];
    }

    foreach ($ips as $ip) {
        if (is_ip_private($ip)) {
            return ['valid' => false, 'reason' => "Host resolves to restricted or private IP address: {$ip}"];
        }
    }

    return [
        'valid' => true,
        'host' => $host,
        'resolved_ip' => $ips[0],
        'reason' => 'URL validation passed.'
    ];
}
