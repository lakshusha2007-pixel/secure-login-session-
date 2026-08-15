# Web Application Firewall (WAF) Configuration & Deployment Guide

This document defines application-level filtering rules implemented in PHP alongside deployment instructions for Cloudflare WAF or reverse-proxy WAF infrastructure.

---

## 1. Hosting Provider Capabilities & Infrastructure Boundaries

> [!IMPORTANT]
> **InfinityFree & Shared PHP Hosting Limitation**: PHP scripts running on InfinityFree cannot create real infrastructure-level edge firewalls or network layer filtering. Infrastructure WAF must be configured at the DNS / Cloudflare level in front of the origin server.

---

## 2. Cloudflare Cloud WAF Rules Configuration

To protect the application against SQL Injection, Cross-Site Scripting (XSS), credential stuffing, and automated bot attacks, deploy the following rules in your Cloudflare Dashboard under **Security > WAF > Custom Rules**:

```json
{
  "rules": [
    {
      "action": "block",
      "expression": "(http.request.uri.path contains \"/admin/\" and not ip.src in {192.168.1.0/24}) or (http.request.uri.query contains \"UNION SELECT\") or (http.request.uri.query contains \"<script>\")",
      "description": "Block SQLi, XSS, and unauthorized admin paths"
    },
    {
      "action": "rate_limit",
      "ratelimit": {
        "characteristics": ["ip.src"],
        "period": 60,
        "requests_per_period": 30
      },
      "expression": "http.request.uri.path contains \"/login.php\" or http.request.uri.path contains \"/api/\"",
      "description": "Rate limit authentication & API requests"
    }
  ]
}
```

---

## 3. Application-Level PHP Defense-in-Depth

The application implements defense-in-depth WAF filtering in PHP (`includes/security.php` & `includes/validation.php`):

1. **Input Schema Validation**: Rejects unexpected fields and malformed data types.
2. **SQL Injection Defense**: Prepared statements with parameterized queries (`mysqli::prepare`) site-wide.
3. **XSS Protection**: Contextual output encoding (`e()`), strict HttpOnly/SameSite session cookies, and strict Content-Security-Policy (CSP) headers with nonces.
4. **Path Traversal Protection**: Strips directory paths (`../`) from file uploads and resource references.
