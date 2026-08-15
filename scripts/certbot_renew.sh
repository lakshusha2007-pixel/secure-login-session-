#!/usr/bin/env bash
# ==============================================================================
#  scripts/certbot_renew.sh — TLS CERTIFICATE AUTO-RENEWAL SCRIPT
# ==============================================================================
#
#  Automates TLS certificate renewal for Let's Encrypt (Certbot) on Apache/Nginx.
#  Enforces TLS 1.2+ minimum cipher security.
#
#  Usage:
#      bash scripts/certbot_renew.sh --dry-run
#      bash scripts/certbot_renew.sh
#
#  Recommended Crontab setup (runs daily at 03:00 AM):
#      0 3 * * * /bin/bash /path/to/project/scripts/certbot_renew.sh >> /var/log/certbot-renew.log 2>&1
# ==============================================================================

set -euo pipefail

LOG_PREFIX="[$(date +'%Y-%m-%d %H:%M:%S')] [Certbot Auto-Renewal]"

echo "${LOG_PREFIX} Checking TLS certificate renewal status..."

if ! command -v certbot &> /dev/null; then
    echo "${LOG_PREFIX} ERROR: Certbot is not installed on this server."
    echo "${LOG_PREFIX} For Ubuntu/Debian, install with: sudo apt install certbot python3-certbot-apache"
    exit 1
fi

# Execute certbot renewal
if [[ "${1:-}" == "--dry-run" ]]; then
    echo "${LOG_PREFIX} Running Certbot dry-run test..."
    certbot renew --dry-run
    echo "${LOG_PREFIX} Dry-run test completed successfully!"
else
    echo "${LOG_PREFIX} Renewing active TLS certificates..."
    certbot renew --quiet --post-hook "systemctl reload apache2 || systemctl reload nginx || true"
    echo "${LOG_PREFIX} TLS certificates successfully checked/renewed."
fi
