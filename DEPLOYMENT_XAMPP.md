# Local Development & Testing Guide — XAMPP (Apache + MySQL)

This guide provides instructions for setting up and running the **Secure Login & Session System** locally using **XAMPP on Windows**.

---

## 1. Prerequisites
- **XAMPP for Windows** (with PHP 8.0+ and MySQL).
- **PHP Extensions**: `mysqli`, `openssl`, `json`, `mbstring`, `fileinfo`.

---

## 2. Setup Instructions

### Step 1: Copy Project Files to XAMPP
Copy the project folder into `C:\xampp\htdocs\secure_auth\` or run directly from your current workspace directory.

---

### Step 2: Configure MySQL Database
1. Start **Apache** and **MySQL** from XAMPP Control Panel.
2. Open phpMyAdmin at `http://localhost/phpmyadmin/`.
3. Create a new database named `secure_login_db`.
4. Import [`database_migration_v3.sql`](file:///c:/Users/LAKSHMANAN/Desktop/secure%20login&%20session/database_migration_v3.sql).

---

### Step 3: Configure `.env` File
Create or update `.env` in the project root:
```ini
APP_ENV=development
APP_URL=http://localhost:8000
APP_ENCRYPTION_KEY=d7a9e3f1c8b2a5d4e6f0a1b3c5d7e9f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4

DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=secure_login_db
DB_PORT=3306

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourgmail@gmail.com
SMTP_PASS=your_app_password
```

---

### Step 4: Run Built-In Web Server or Apache
Option A (PHP Built-in Server):
```powershell
php -S localhost:8000
```
Then open: `http://localhost:8000`

Option B (XAMPP Apache VirtualHost):
Add to `C:\xampp\apache\conf\extra\httpd-vhosts.conf`:
```apache
<VirtualHost *:80>
    DocumentRoot "C:/Users/LAKSHMANAN/Desktop/secure login& session"
    ServerName secureauth.local
    <Directory "C:/Users/LAKSHMANAN/Desktop/secure login& session">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

---

## 3. Local Verification Commands

```powershell
# 1. Run SAST Security Code Scanner
php scripts/sast_scan.php

# 2. Run Synthetic Health Check
php scripts/synthetic_health_check.php

# 3. Run Security Regression Test Suite
php tests/security_regression_test.php

# 4. Run DAST Dynamic HTTP Scan
php scripts/dast_scan.php
```
