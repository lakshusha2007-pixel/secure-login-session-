# Secure Login & Session Management Module

**Secure Login, Session Protection, Logout, and Basic Brute-Force Resistance**

A complete user-authentication module built with **Core PHP 8+, PHP Sessions, MySQL, HTML5, CSS3, and Vanilla JavaScript** — no frameworks, no Composer, no external libraries. Fully compatible with **InfinityFree Hosting**.

This project complements the existing **registration system (Problem 04)**, whose users are stored in the `users` table with passwords hashed using `password_hash()`.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Stage 0 — Planning & Authentication Architecture](#stage-0--planning--authentication-architecture)
3. [Stage 1 — Secure Session Configuration](#stage-1--secure-session-configuration)
4. [Stage 2 — Login System](#stage-2--login-system)
5. [Stage 3 — Protected Dashboard](#stage-3--protected-dashboard)
6. [Stage 4 — Logout](#stage-4--logout)
7. [Stage 5 — Brute-Force Protection](#stage-5--brute-force-protection)
8. [Security Requirements & Why They Matter](#security-requirements--why-they-matter)
9. [Database Setup](#database-setup)
10. [InfinityFree Deployment Guide](#infinityfree-deployment-guide)
11. [Testing Guide](#testing-guide)
12. [Acceptance Criteria Checklist](#acceptance-criteria-checklist)

---

## Project Structure

```
project/
│
├── config/
│   ├── database.php        # MySQL connection (MySQLi + prepared statements)
│   └── session.php         # Secure session cookie config + idle timeout
│
├── includes/
│   ├── auth.php            # Auth helpers + brute-force + CSRF helpers
│   ├── header.php          # HTML head, security headers, navigation
│   └── footer.php          # Footer + JS include
│
├── assets/
│   ├── css/
│   │   └── style.css       # Modern responsive design system
│   └── js/
│       └── main.js         # Vanilla JS (toggle, validation, logout confirm)
│
├── index.php               # Public landing page
├── login.php               # Secure login + brute-force lockout
├── dashboard.php           # Protected page (requires login)
├── logout.php              # Full session destruction
├── setup_check.php         # Automated diagnostic & 1-click database installer tool
└── README.md               # This document
```

---

## Stage 0 — Planning & Authentication Architecture

### Authentication Flow

```
┌──────────┐     ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Visitor │────▶│   login.php │────▶│   Session    │────▶│  dashboard   │
│ Browser  │     │  (POST form)│     │  Regenerate  │     │  (protected) │
└──────────┘     └──────┬──────┘     └──────┬───────┘     └──────┬───────┘
        ▲               │                   │                    │
        │               ▼                   ▼                    ▼
        │        ┌──────────────┐    ┌─────────────┐     ┌─────────────┐
        │        │  users table │    │ secure cookie│    │  logout.php │
        │        │ (prepared SQL)│   │ HttpOnly +  │     │  destroy    │
        └────────│ password_hash │    │ Secure + Lax│    │  session    │
                 └──────────────┘    └─────────────┘     └─────────────┘
```

### Login Process

1. User submits email + password to `login.php` (POST).
2. Server checks the **brute-force lock** for that email (max 5 failures / 5 min).
3. Server validates the **CSRF token** (defence in depth).
4. Server validates the email format + password non-empty.
5. Server runs a **prepared statement**: `SELECT ... FROM users WHERE email = ?`.
6. Server calls **`password_verify()`** against the stored hash — never compares plain text.
7. On success: reset attempt counter → **`session_regenerate_id(true)`** → store `user_id`, `email`, `role` in the session → redirect to `dashboard.php`.
8. On failure: increment the attempt counter, show the **generic** message `Invalid credentials.` (same for wrong password and unknown email → no username enumeration).

### Session Lifecycle

- **Start:** `config/session.php` runs `session_set_cookie_params([...])` then `session_start()`.
- **Login:** the session ID is **regenerated** so any pre-planted ID becomes useless.
- **Use:** every request updates `last_activity` (sliding 30-minute idle timeout).
- **Expiry:** if inactive for 30 minutes, the session is destroyed server-side and the user is redirected to `login.php`.
- **Browser close:** the cookie is a *session cookie* (`lifetime = 0`), so closing the browser also ends it.
- **Logout:** the session and its cookie are fully destroyed.

### Protected Pages

Every protected page (e.g. `dashboard.php`) starts with `require_login()`, which:

```php
if (!is_logged_in()) {
    header('Location: login.php');
    exit;
}
```

Guests are redirected and `exit` halts all further rendering — the protected content can never be generated.

### Logout Process

`logout.php` (in order):
1. Deletes the session cookie (`setcookie` with a past expiry).
2. `session_unset()` — clears all session data.
3. `session_destroy()` — removes the server-side session.
4. Redirects to `login.php?logged_out=1`.

Combined with the `Cache-Control: no-store` headers, the browser Back button can no longer show the dashboard after logout.

### Brute-Force Prevention

Tracked **per email address inside the session** (Method 1):
- Maximum **5** failed attempts.
- Lock for **5 minutes**.
- Counter resets on successful login and automatically after the lock window expires.
- On lock, the user sees: `Too many login attempts. Please try again later.`

### Cookie Security

The session cookie is hardened with four options:

| Option | Value | Purpose |
|---|---|---|
| `secure` | `true` | Sent only over HTTPS → cannot be sniffed on Wi-Fi |
| `httponly` | `true` | Invisible to JavaScript → XSS cannot steal it |
| `samesite` | `Lax` | Not sent cross-site → blocks CSRF cookie reuse |
| `lifetime` | `0` | Session cookie → gone when the browser closes |

---

## Stage 1 — Secure Session Configuration

File: `config/session.php`

```php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Lax'
]);
```

| Option | Meaning |
|---|---|
| `lifetime => 0` | Cookie lives only while the browser is open. Server-side idle timeout handles inactivity instead. |
| `path => '/'` | Cookie sent to every page of the domain, so a login on one folder applies to the whole site. |
| `secure => true` | HTTPS-only. InfinityFree serves HTTPS by default, so this is safe to enable. |
| `httponly => true` | JavaScript cannot read the cookie via `document.cookie`. |
| `samesite => 'Lax'` | The cookie is withheld on cross-site sub-requests, blocking CSRF-style reuse. |

The file also adds a **sliding inactivity timeout**: if `last_activity` is older than 30 minutes, the session is destroyed and the user is sent to `login.php`.

Session fixation is defeated separately with `session_regenerate_id(true)` immediately after a successful login (in `includes/auth.php`).

---

## Stage 2 — Login System

File: `login.php`

**Backend flow (server-side only — never trust the browser):**

1. **CSRF check** — forms must carry the session token (`hash_equals`).
2. **Validation** — `filter_var(..., FILTER_VALIDATE_EMAIL)` + non-empty password.
3. **Brute-force check** — `is_login_locked($email)` before doing any work.
4. **Prepared statement** — the query uses a `?` placeholder:

```php
$stmt = $conn->prepare('SELECT id, fullname, email, password, role FROM users WHERE email = ? LIMIT 1');
$stmt->bind_param('s', $email);
```

5. **Password verification**:

```php
$passwordOk = $user !== null && password_verify($password, $user['password']);
```

6. **Success:**

```php
regenerate_session();                       // kills fixation
$_SESSION['user_id']  = $user['id'];
$_SESSION['email']    = $user['email'];
$_SESSION['role']     = $user['role'];
header('Location: dashboard.php');
exit;
```

7. **Failure** — a single identical message for every failure reason:

> **Invalid credentials.**

This prevents attackers from learning whether an email exists (username / email enumeration).

---

## Stage 3 — Protected Dashboard

File: `dashboard.php`

```php
require_once __DIR__ . '/includes/auth.php';
require_login();   // guests → redirect to login.php + exit
```

Shows the user's **full name, ID, email, role** and the current **session ID** (educational — you can compare it before/after login to see regeneration in action). A **Logout** button is a POST form carrying the CSRF token, so logout can't be triggered by a malicious page.

---

## Stage 4 — Logout

File: `logout.php`

```php
setcookie(session_name(), '', time() - 42000, ...); // delete the cookie
$_SESSION = [];
session_unset();
session_destroy();
header('Location: login.php?logged_out=1');
exit;
```

Accessing `dashboard.php` after logout is impossible: `require_login()` sends you back to `login.php`, and the `no-store` cache header stops the browser from resurrecting a cached copy via the Back button.

---

## Stage 5 — Brute-Force Protection

Implemented as **Method 1 (session-based)**, per-email:

- `MAX_ATTEMPTS = 5`
- `LOCK_SECONDS  = 300` (5 minutes)
- `record_failed_attempt($email)` — on every failure
- `reset_failed_attempts($email)` — on success
- `is_login_locked($email)` / `get_lock_remaining($email)` — checks before processing

**Why per-email?** Attackers usually pick *one* victim account and hammer it. Locking per email stops exactly that. Because counters live in the attacker's own session, real users logging in from their own browsers are never blocked, and the `users` table is never modified.

**Honest limitation:** session-based counters vanish if the attacker clears cookies. Method 2 (a `failed_logins` table keyed by IP + email) is stronger; it is described in the README as an optional upgrade.

On lock the user sees:

> **Too many login attempts. Please try again later. Try again in about X minutes.**

---

## Security Requirements & Why They Matter

| Measure | Where | Why |
|---|---|---|
| **Prepared Statements** | `login.php` | User input can never become SQL syntax → no SQL injection |
| **`password_hash()`** | registration (Problem 04) | bcrypt salt + cost, one-way, not reversible |
| **`password_verify()`** | `login.php` | Timing-safe hash comparison; never compares plain text |
| **`session_regenerate_id(true)`** | `auth.php` | New random ID at login → defeats session fixation |
| **HttpOnly** | `config/session.php` | JS can't read the cookie → blocks XSS cookie theft |
| **Secure** | `config/session.php` | HTTPS only → blocks sniffing on shared networks |
| **SameSite=Lax** | `config/session.php` | No cross-site cookie sending → blocks CSRF reuse |
| **`htmlspecialchars()`** | `e()` helper everywhere | Output is escaped → blocks XSS |
| **Generic errors** | `login.php` | Same message for all failures → blocks enumeration |
| **Idle timeout** | `config/session.php` | Abandoned sessions die after 30 min |
| **CSRF token** | `auth.php` + forms | Synchronizer token on state-changing forms |
| **`Cache-Control: no-store`** | `includes/header.php` | Back button can't resurrect protected pages after logout |

---

## Database Setup

The module assumes the `users` table already exists (from Problem 04). Reference schema:

```sql
CREATE TABLE users (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    fullname   VARCHAR(100) NOT NULL,
    email      VARCHAR(255) NOT NULL,
    password   VARCHAR(255) NOT NULL,   -- password_hash() output
    role       VARCHAR(50)  NOT NULL DEFAULT 'user',
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert a test user (password: "Test@123")
INSERT INTO users (fullname, email, password, role)
VALUES (
    'Demo User',
    'demo@example.com',
    '$2y$10$e0MYzXyjpJS7Pd0RVvHwHeFxWfRdr2C0E0q0h0xqC0WJYV8U0Pz5C', -- replace with your own password_hash() output
    'user'
);
```

> **Important:** the hash above is a placeholder. Generate a real hash with `php -r "echo password_hash('Test@123', PASSWORD_DEFAULT);"` or a small PHP script, then insert it.

---

## InfinityFree Deployment Guide

1. **Create your MySQL database** in the InfinityFree control panel. Copy the host (e.g. `sqlXXX.epizy.com`), username, password and database name.
2. **Edit `config/database.php`** and replace the four constants (`DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME`) with your InfinityFree values. Note: on InfinityFree the host is **not** `localhost`.
3. **Create the `users` table** using phpMyAdmin (see SQL above) and insert a test user.
4. **Upload the whole project folder** to `htdocs/` via the InfinityFree File Manager or FTP.
5. Open your site — it is served over **HTTPS**, which satisfies the `secure` cookie option.
6. **Done.** No Composer, no CLI, no frameworks required.

> **PHP version note:** this code uses PHP 8 features (named session params, arrow-safe syntax, typed functions). InfinityFree offers PHP 8+ — select it in the control panel (Account → PHP Version) if needed.

---

## Testing Guide

| # | Test | Steps | Expected Result |
|---|---|---|---|
| 1 | **Correct login** | Login with the seeded user | Redirect to `dashboard.php`; welcome banner shows your name/email/role; session ID visible |
| 2 | **Wrong password** | Correct email, wrong password | Stays on `login.php`; shows `Invalid credentials.` (no hint which field was wrong) |
| 3 | **Unknown email** | Unregistered email, any password | Same generic `Invalid credentials.` — cannot tell if the email exists |
| 4 | **Session expired** | Wait 30+ minutes idle (or temporarily lower `$inactivityLimit`), then load dashboard | Redirected to `login.php` |
| 5 | **Direct dashboard access** | Open `dashboard.php` while logged out / new incognito window | Redirected to `login.php` |
| 6 | **Logout** | Click Logout on the dashboard | Cookie cleared, session destroyed, redirected to `login.php?logged_out=1` with a confirmation banner |
| 7 | **Back button after logout** | After logout, press Back | No dashboard; `no-store` headers force `login.php`; even a cached frame redirects on any interaction |
| 8 | **Multiple failed attempts** | Fail login 5 times for the same email | 6th attempt blocked with `Too many login attempts. Please try again later.` |
| 9 | **Lock expiry** | Wait 5 minutes after lockout, try again | Lock cleared; can attempt login again |
| 10 | **Browser refresh on login page** | Refresh after a failed POST | No resubmission warning; error not duplicated |
| 11 | **Session regeneration** | Login; note session ID → logout → login again; compare IDs | IDs differ (proves `session_regenerate_id`) |
| 12 | **XSS attempt** | Enter `<script>alert(1)</script>` as name/email | Rendered as plain text, never executed |
| 13 | **SQL injection attempt** | Enter `' OR '1'='1` as email/password | No bypass; prepared statements neutralise it |

---

## Acceptance Criteria Checklist

- [x] Passwords verified using `password_verify()`
- [x] Passwords stored using `password_hash()` (registration, Problem 04)
- [x] Secure PHP sessions implemented (`session_set_cookie_params` + `session_start`)
- [x] Dashboard protected from unauthorized access (`require_login()`)
- [x] Logout completely destroys the session (cookie + data + session)
- [x] Guests are redirected to `login.php`
- [x] Generic `Invalid credentials.` message — no username/email enumeration
- [x] Basic brute-force protection (5 attempts / 5 min lockout)
- [x] Session fixation prevented (`session_regenerate_id(true)` after login)
- [x] Session hijacking mitigated (HttpOnly + Secure + idle timeout)
- [x] Secure cookies configured (HttpOnly, Secure, SameSite=Lax)
- [x] SQL injection prevented (prepared statements)
- [x] XSS prevented (`htmlspecialchars()` on all output)
- [x] Fully compatible with InfinityFree Hosting (Core PHP, no Composer)
- [x] Well-documented, beginner-friendly code
- [x] Clean, modern, responsive user interface
- [x] Production-ready and fully functional

---

### Optional upgrade: MySQL-based brute-force tracking (Method 2)

To survive cookie-clearing attackers, replace the session counters with a table:

```sql
CREATE TABLE failed_logins (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    email       VARCHAR(255) NOT NULL,
    ip_address  VARCHAR(45)  NOT NULL,
    attempted_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Locking logic then counts rows per email/IP within the last 5 minutes instead of reading session counters. All other logic (5 attempts, 5-minute window, reset on success) stays identical.
