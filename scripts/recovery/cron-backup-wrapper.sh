#!/usr/bin/env bash
# CipherVault Daily Recovery Upload Wrapper with Operational Alerting
# Place at /opt/ciphervault-ui/cron-backup-wrapper.sh on cv-web-ui
set -euo pipefail

LOG_FILE="/opt/ciphervault-ui/recovery-upload.log"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT_SCRIPT="${SCRIPT_DIR}/backup_alert.py"
UPLOAD_SCRIPT="${SCRIPT_DIR}/recovery-upload.sh"

# Signal start of backup to Healthchecks.io or snitch
if [[ -f "${ALERT_SCRIPT}" ]]; then
    python3 "${ALERT_SCRIPT}" --status start --service "ciphervault-daily-recovery" || true
fi

# Execute the core upload script, redirecting output to the log file
if "${UPLOAD_SCRIPT}" >> "${LOG_FILE}" 2>&1; then
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') [cron-wrapper] Backup succeeded." >> "${LOG_FILE}"
    if [[ -f "${ALERT_SCRIPT}" ]]; then
        python3 "${ALERT_SCRIPT}" \
            --status success \
            --service "ciphervault-daily-recovery" \
            --message "Daily recovery backup uploaded successfully to gs://cv-account-recovery-108687509435" \
            --log-file "${LOG_FILE}" || true
    fi
    exit 0
else
    EXIT_CODE=$?
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') [cron-wrapper] Backup FAILED with code ${EXIT_CODE}." >> "${LOG_FILE}"
    if [[ -f "${ALERT_SCRIPT}" ]]; then
        python3 "${ALERT_SCRIPT}" \
            --status failure \
            --service "ciphervault-daily-recovery" \
            --message "Daily recovery backup FAILED with exit code ${EXIT_CODE} on $(hostname)" \
            --log-file "${LOG_FILE}" || true
    fi
    exit "${EXIT_CODE}"
fi
