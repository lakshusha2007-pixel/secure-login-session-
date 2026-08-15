# Infrastructure Hardening, CDN/DDoS & Environment Isolation Guide

This document covers network firewall requirements, CDN/DDoS protection setup, multi-environment isolation, and infrastructure public exposure reviews.

---

## 1. Network Firewall & Least Privilege Port Requirements

For dedicated or VPS deployment environments (e.g. AWS EC2, GCP Compute Engine, DigitalOcean, XAMPP local server), apply network security group rules enforcing the principle of least privilege:

| Port | Service | Direction | Access Policy | Justification |
|---|---|---|---|---|
| **443** | HTTPS | Inbound | Public (`0.0.0.0/0`) | Encrypted public web traffic |
| **80** | HTTP | Inbound | Public (`0.0.0.0/0`) | Automatic 301 redirect to HTTPS 443 |
| **3306** | MySQL | Inbound | **BLOCKED** | Database must NOT be exposed to public internet. Bind to `127.0.0.1`. |
| **22** | SSH | Inbound | Restricted | Allow only authorized admin IP ranges or VPN bastions. |

> [!NOTE]
> **InfinityFree Hosting Note**: Network port filtering is managed entirely by InfinityFree infrastructure. Remote MySQL access is disabled by default on InfinityFree.

---

## 2. CDN & DDoS Protection Setup

1. **Cloudflare CDN Integration**:
   - Point domain Nameservers to Cloudflare.
   - Set SSL/TLS Encryption Mode to **Full (Strict)**.
   - Enable Cloudflare Bot Fight Mode and Under Attack Mode if experiencing HTTP flood attacks.

2. **Cache Protection for Authenticated Pages**:
   - All authenticated application responses emit HTTP headers:
     `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`
   - Prevents CDNs or intermediate proxies from caching sensitive private user data or API responses.

---

## 3. Development vs Staging vs Production Environment Isolation

The system uses `.env` files outside public web access to isolate environment configurations:

- **Production Mode**:
  `APP_ENV=production`
  `APP_DEBUG=false`
  `CSP_REPORT_ONLY=false`
  Detailed PHP error tracebacks are hidden from visitors, logging securely to `logs/error.log` via `includes/error_handler.php`.

- **Development Mode**:
  `APP_ENV=development`
  `APP_DEBUG=true`

> [!WARNING]
> **CRITICAL RULE**: `APP_DEBUG=true` MUST NEVER BE USED IN PRODUCTION.

---

## 4. Infrastructure Public Exposure Audit Results

An audit of the repository and file structure confirmed:
- Direct access to `.env`, `.git`, `.sql`, `.log`, and `.bak` files is blocked via `.htaccess`.
- Database backup scripts are located outside public web roots or protected by directory `.htaccess` rules (`Deny from all`).
- Passwords and master encryption keys are NOT hardcoded in source code.
