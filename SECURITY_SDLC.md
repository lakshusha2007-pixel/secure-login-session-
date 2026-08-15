# Supply Chain & SDLC Security Policy

## 1. Branch Protection & Pull Request Governance

- **Main Branch Protection**: Direct pushes to `main` / `master` are strictly disabled.
- **Code Review**: All security-sensitive changes require at least **one peer review approval** from a designated Security Lead.
- **CI Gate Verification**: PRs cannot be merged unless all SAST code scans (`php scripts/sast_scan.php`), regression tests (`php tests/security_regression_test.php`), and concurrency tests (`php tests/concurrency_test.php`) pass with 0 failures.

---

## 2. Secret Management & Hardcoding Rules

- **Zero Secret Commits**: Production database credentials, SMTP passwords, API keys, and OAuth client secrets MUST NEVER be committed to Git.
- **Environment Configuration**: All secrets are populated via `.env` loaded securely by `config/env.php`.
- **Git Ignore Safeguards**: `.env` is explicitly ignored in `.gitignore`. A template placeholder file `.env.example` is committed for reference.

---

## 3. Automated SAST & DAST Scanning

Run automated Static and Dynamic scans during CI/CD execution:
```bash
# Static Application Security Testing (SAST)
php scripts/sast_scan.php

# Dynamic Application Security Testing (DAST against staging)
php scripts/dast_scan.php

# Security Regression Test Suite
php tests/security_regression_test.php

# Race-Condition & Concurrency Test Suite
php tests/concurrency_test.php
```
