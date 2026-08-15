# Production Deployment Guide — InfinityFree Hosting

This guide provides step-by-step instructions for deploying the **Secure Login & Session System** to **InfinityFree Free Web Hosting** (or any cPanel/vPanel PHP hosting environment).

---

## 1. Hosting Environment Prerequisites
- **PHP Version**: PHP 8.0, 8.1, or 8.2 (configured via InfinityFree Control Panel).
- **MySQL Database**: 1 MySQL Database instance created via InfinityFree MySQL Databases tool.
- **SSL Certificate**: Free SSL Certificate issued via InfinityFree SSL Certificates tool (ZeroSSL / Let's Encrypt).

---

## 2. Step-by-Step Deployment Procedure

### Step 1: Upload Project Files via FTP / File Manager
1. Log in to your InfinityFree Account Control Panel (vPanel).
2. Open **File Manager** and navigate to the `htdocs/` folder (web root).
3. Upload all project files directly into `htdocs/`:
   - All `.php` files (`index.php`, `login.php`, `register.php`, `dashboard.php`, `profile.php`, etc.)
   - Folders: `config/`, `includes/`, `assets/`, `admin/`, `api/`, `scripts/`, `uploads/`, `logs/`, `backups/`
   - `.htaccess` file

---

### Step 2: Database Setup & Migration Import
1. In InfinityFree Control Panel, click **MySQL Databases** and create a new database (e.g. `epiz_12345678_secureauth`).
2. Note down your database credentials:
   - **MySQL Hostname**: `sqlxxx.epizy.com`
   - **MySQL Database Name**: `epiz_12345678_secureauth`
   - **MySQL Username**: `epiz_12345678`
   - **MySQL Password**: *(Your account vPanel password)*
3. Click **phpMyAdmin** to open the database management tool.
4. Select your database, click the **Import** tab, choose [`database_migration_v3.sql`](file:///c:/Users/LAKSHMANAN/Desktop/secure%20login&%20session/database_migration_v3.sql), and click **Go**.

---

### Step 3: Configure Production Environment (`.env`)
1. In the `htdocs/` directory, create or edit the `.env` file with your InfinityFree production values:
   ```ini
   APP_ENV=production
   APP_URL=https://yourdomain.infinityfreeapp.com
   APP_ENCRYPTION_KEY=d7a9e3f1c8b2a5d4e6f0a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4

   DB_HOST=sqlxxx.epizy.com
   DB_USER=epiz_12345678
   DB_PASS=YourVpanelPassword
   DB_NAME=epiz_12345678_secureauth
   DB_PORT=3306

   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=yourgmail@gmail.com
   SMTP_PASS=your_app_password
   ```

---

### Step 4: Issue & Install Free SSL Certificate (HTTPS [P0])
1. In InfinityFree Control Panel, click **SSL Certificates**.
2. Select your domain name and choose **ZeroSSL** or **Let's Encrypt** (Free).
3. Follow the automated CNAME DNS validation steps to generate the certificate.
4. Click **Install SSL Certificate Automatically**.
5. Verify HTTPS access by opening: `https://yourdomain.infinityfreeapp.com`

---

### Step 5: Verify `.htaccess` Site-Wide HTTPS & Header Protection
Ensure `.htaccess` in `htdocs/` includes HTTP -> HTTPS redirection and security headers:
```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
```

---

## 3. Server & DNS Settings Requiring Hosting/DNS Control

| Security Control | Configurable via PHP / .htaccess | Requiring External Hosting / DNS Configuration | Instructions |
|---|---|---|---|
| **HTTPS Redirection & HSTS** | ✅ Yes (`.htaccess`) | ❌ No | Active in `.htaccess` and `includes/header.php`. |
| **Directory Protection & Denies** | ✅ Yes (`.htaccess`) | ❌ No | Active in `uploads/.htaccess`, `logs/.htaccess`, `backups/.htaccess`. |
| **TLS 1.2+ / Weak TLS Disable** | ❌ No (Server Level) | ✅ Yes (InfinityFree Infrastructure) | InfinityFree web servers automatically disable SSLv3, TLS 1.0, and TLS 1.1 on free SSL domains. |
| **DNS CAA Record** | ❌ No (PHP Level) | ✅ Yes (DNS Control Panel) | Add a DNS CAA record at your DNS provider:<br>`0 issue "letsencrypt.org"` |
| **WAF / DDoS Protection** | ❌ No (PHP Level) | ✅ Yes (Cloudflare Edge proxy) | Point your domain's nameservers to Cloudflare to enable DDoS shield & WAF rules. |
