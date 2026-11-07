#!/usr/bin/env python3
"""CipherVault Backup & Recovery Alert Dispatcher (stdlib only).

Dispatches operational status pings, failure notifications, and health heartbeats
for scheduled backups and custody copy operations.

Supported Alert Destinations:
1. Healthchecks.io / Dead Man's Snitch ping URLs
2. Incoming Webhooks (Slack, Discord, MS Teams, Generic JSON)
3. PagerDuty Events API v2

Zero external dependencies: uses Python urllib.request only.
Plaintext secrets and cryptographic keys are strictly excluded from all payloads.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT_SECS = 15
MAX_LOG_TAIL_BYTES = 4096
MAX_LOG_LINES = 25


def sanitize_message(text: str) -> str:
    """Ensure message text contains no credential-shaped material."""
    if not text:
        return ""
    sanitized = text
    for prefix in ("cvst1.", "age1", "Bearer "):
        idx = 0
        while True:
            pos = sanitized.find(prefix, idx)
            if pos == -1:
                break
            # Find end of token word (whitespace or newline)
            end_pos = pos + len(prefix)
            while end_pos < len(sanitized) and not sanitized[end_pos].isspace() and sanitized[end_pos] not in (',', ';', '"', "'"):
                end_pos += 1
            sanitized = sanitized[:pos] + prefix + "[REDACTED]" + sanitized[end_pos:]
            idx = pos + len(prefix) + len("[REDACTED]")
    return sanitized.strip()


def read_log_tail(log_file: Path) -> str:
    """Read the last few lines of a log file safely without leaking unbounded memory."""
    if not log_file or not log_file.is_file():
        return ""
    try:
        size = log_file.stat().st_size
        offset = max(0, size - MAX_LOG_TAIL_BYTES)
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            if offset > 0:
                f.seek(offset)
            lines = f.readlines()
        tail = "".join(lines[-MAX_LOG_LINES:])
        return sanitize_message(tail)
    except Exception as e:
        return f"[Failed to read log tail: {e}]"


def send_http_request(url: str, payload_dict: dict = None, method: str = "POST") -> tuple[bool, str]:
    """Send an HTTP request with JSON payload or plain GET/POST."""
    headers = {
        "User-Agent": "CipherVault-BackupAlert/1.0",
    }
    data = None
    if payload_dict is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload_dict).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            status = resp.status
            return (200 <= status < 300, f"HTTP {status}")
    except urllib.error.HTTPError as e:
        return (False, f"HTTPError {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        return (False, f"URLError: {e.reason}")
    except Exception as e:
        return (False, f"Error: {e}")


def dispatch_healthcheck(base_url: str, status: str, log_summary: str = "") -> tuple[bool, str]:
    """Ping healthchecks.io compatible service.
    
    URL patterns:
    - start:   <base_url>/start
    - success: <base_url> (or <base_url>/0)
    - failure: <base_url>/fail (or <base_url>/1)
    """
    clean_url = base_url.rstrip("/")
    if status == "start":
        target = f"{clean_url}/start"
    elif status == "failure":
        target = f"{clean_url}/fail"
    else:
        target = clean_url

    data = log_summary.encode("utf-8") if log_summary and status == "failure" else None
    headers = {"User-Agent": "CipherVault-BackupAlert/1.0"}
    req = urllib.request.Request(target, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECS) as resp:
            return (200 <= resp.status < 300, f"Healthcheck ping OK ({resp.status})")
    except Exception as e:
        return (False, f"Healthcheck ping failed: {e}")


def dispatch_webhook(webhook_url: str, event_data: dict) -> tuple[bool, str]:
    """Dispatch formatted webhook payload to Slack, Discord, Teams, or Generic endpoint."""
    is_slack_discord = any(domain in webhook_url for domain in ("slack.com", "discord.com", "office.com"))
    status = event_data.get("status", "unknown")
    host = event_data.get("host", socket.gethostname())
    service = event_data.get("service", "ciphervault-backup")
    message = event_data.get("message", "")
    log_tail = event_data.get("log_tail", "")

    if is_slack_discord:
        emoji = "🚨" if status == "failure" else ("✅" if status == "success" else "ℹ️")
        color = "#e02424" if status == "failure" else ("#0e9f6e" if status == "success" else "#3f83f8")
        text = f"{emoji} *CipherVault Alert: {service} on {host}* ({status.upper()})\n> {message}"
        if log_tail and status == "failure":
            text += f"\n```\n{log_tail[-1500:]}\n```"

        payload = {
            "text": text,
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Service", "value": service, "short": True},
                        {"title": "Host", "value": host, "short": True},
                        {"title": "Status", "value": status.upper(), "short": True},
                        {"title": "Timestamp", "value": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()), "short": True},
                    ]
                }
            ]
        }
    else:
        payload = event_data

    return send_http_request(webhook_url, payload, method="POST")


def dispatch_pagerduty(routing_key: str, event_data: dict) -> tuple[bool, str]:
    """Dispatch alert to PagerDuty Events API v2."""
    status = event_data.get("status", "unknown")
    severity = "critical" if status == "failure" else "info"
    action = "trigger" if status == "failure" else "resolve"
    host = event_data.get("host", socket.gethostname())
    service = event_data.get("service", "ciphervault-backup")

    payload = {
        "routing_key": routing_key,
        "event_action": action,
        "dedup_key": f"{service}-{host}",
        "payload": {
            "summary": f"CipherVault {service} {status} on {host}: {event_data.get('message', '')}",
            "source": host,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "custom_details": {
                "service": service,
                "status": status,
                "log_tail": event_data.get("log_tail", "")[:1000],
            }
        }
    }
    pd_url = "https://events.pagerduty.com/v2/enqueue"
    return send_http_request(pd_url, payload, method="POST")


def load_config(config_path: str = None) -> dict:
    """Load alert configuration from file and environment variables."""
    cfg = {}
    if config_path and Path(config_path).is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                cfg = raw.get("alert", raw)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load alert config {config_path}: {e}\n")

    # Environment variables take precedence
    if "CIPHERVAULT_ALERT_WEBHOOK_URL" in os.environ:
        cfg["webhook_url"] = os.environ["CIPHERVAULT_ALERT_WEBHOOK_URL"]
    if "CIPHERVAULT_ALERT_HEALTHCHECK_URL" in os.environ:
        cfg["healthcheck_url"] = os.environ["CIPHERVAULT_ALERT_HEALTHCHECK_URL"]
    if "CIPHERVAULT_ALERT_PAGERDUTY_KEY" in os.environ:
        cfg["pagerduty_routing_key"] = os.environ["CIPHERVAULT_ALERT_PAGERDUTY_KEY"]

    return cfg


def run_alert(
    status: str,
    message: str,
    service: str = "ciphervault-account-custody",
    log_file: str = None,
    config_path: str = None,
    dry_run: bool = False,
) -> bool:
    """Main alert dispatch routine."""
    cfg = load_config(config_path)
    host = socket.gethostname()
    log_tail = read_log_tail(Path(log_file)) if log_file else ""

    event_data = {
        "service": service,
        "status": status,
        "host": host,
        "platform": platform.platform(),
        "timestamp_utc": int(time.time()),
        "timestamp_rfc3339": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "message": sanitize_message(message),
        "log_tail": log_tail,
    }

    destinations_found = False
    all_ok = True

    # 1. Healthchecks.io ping
    hc_url = cfg.get("healthcheck_url")
    if hc_url:
        destinations_found = True
        if dry_run:
            print(f"[dry-run] Healthcheck ping -> {hc_url} (status: {status})")
        else:
            ok, resp = dispatch_healthcheck(hc_url, status, log_tail)
            if not ok:
                sys.stderr.write(f"Alert warning: {resp}\n")
                all_ok = False
            else:
                print(f"Healthcheck ping sent: {resp}")

    # 2. Webhook
    webhook_url = cfg.get("webhook_url")
    if webhook_url:
        destinations_found = True
        if dry_run:
            print(f"[dry-run] Webhook POST -> {webhook_url[:30]}... (status: {status})")
        else:
            ok, resp = dispatch_webhook(webhook_url, event_data)
            if not ok:
                sys.stderr.write(f"Alert warning: {resp}\n")
                all_ok = False
            else:
                print(f"Webhook notification sent: {resp}")

    # 3. PagerDuty
    pd_key = cfg.get("pagerduty_routing_key")
    if pd_key:
        destinations_found = True
        if dry_run:
            print(f"[dry-run] PagerDuty enqueue -> key {pd_key[:6]}... (status: {status})")
        else:
            ok, resp = dispatch_pagerduty(pd_key, event_data)
            if not ok:
                sys.stderr.write(f"Alert warning: {resp}\n")
                all_ok = False
            else:
                print(f"PagerDuty event sent: {resp}")

    if not destinations_found:
        print(f"Notice: No alert destinations configured. Event: [{status.upper()}] {message}")

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="CipherVault Backup & Custody Alert Dispatcher")
    parser.add_argument("--status", choices=["success", "failure", "start"], required=True,
                        help="Operation status to report")
    parser.add_argument("--message", default="", help="Description or error message")
    parser.add_argument("--service", default="ciphervault-account-custody", help="Service name")
    parser.add_argument("--log-file", help="Path to execution log file to tail on failure")
    parser.add_argument("--config", help="Path to alert configuration JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without network calls")

    args = parser.parse_args()
    success = run_alert(
        status=args.status,
        message=args.message,
        service=args.service,
        log_file=args.log_file,
        config_path=args.config,
        dry_run=args.dry_run,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
