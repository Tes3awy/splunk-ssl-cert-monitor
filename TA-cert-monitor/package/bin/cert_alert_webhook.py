#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk Modular Alert Action: SSL Expiration Webhook
Dispatches structured search results for expiring certificates to an external webhook.
Version: 2.0.0
"""

import gzip
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

# Inject app-level vendored lib directory for solnlib
BIN_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(BIN_DIR)
LIB_DIR = os.path.join(APP_DIR, "lib")
if os.path.exists(LIB_DIR) and LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

try:
    from solnlib import log

    logger = log.Logs().get_logger("cert_alert_webhook")
except ImportError:
    import logging

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logger = logging.getLogger("cert_alert_webhook")


def send_webhook(payload):
    config = payload.get("configuration", {})
    webhook_url = config.get("webhook_url")

    if not webhook_url:
        logger.error("Configuration missing: param.webhook_url is empty.")
        return 1

    parsed_url = urllib.parse.urlparse(webhook_url)
    if parsed_url.scheme != "https":
        logger.error(
            f"Insecure URL scheme '{parsed_url.scheme}'. Only HTTPS endpoints are permitted."
        )
        return 2

    # Extract alert metadata provided by Splunk
    search_name = payload.get("search_name", "SSL Certificate Alert")
    severity = config.get("severity", "critical")
    results_file = payload.get("results_file")
    sid = payload.get("sid", "")

    # Read sample records from Splunk dispatch file if present
    results_summary = []
    if results_file and os.path.exists(results_file):
        try:
            open_func = gzip.open if results_file.endswith(".gz") else open
            with open_func(
                results_file, "rt", encoding="utf-8", errors="replace"
            ) as rf:
                results_summary = [line.strip() for line in rf][:25]
        except Exception as read_err:
            logger.warning(f"Could not parse results_file {results_file}: {read_err}")

    alert_data = {
        "source": "Splunk TA-cert-monitor",
        "search_name": search_name,
        "sid": sid,
        "severity": severity,
        "app": payload.get("app", "TA-cert-monitor"),
        "owner": payload.get("owner", "nobody"),
        "sample_records": results_summary,
    }

    body_bytes = json.dumps(alert_data).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body_bytes,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Splunk-TA-cert-monitor-Webhook/2.0.0",
        },
    )

    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            logger.info(
                f"Alert webhook delivered successfully to {webhook_url}, status={resp.status}"
            )
            return 0
    except Exception as exc:
        logger.error(f"Failed to deliver alert webhook: {exc}")
        return 3


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        try:
            raw_input_data = sys.stdin.read()
            if not raw_input_data.strip():
                logger.error("No JSON payload received on stdin.")
                sys.exit(1)

            payload_data = json.loads(raw_input_data)
            sys.exit(send_webhook(payload_data))
        except Exception as e:
            logger.error(f"Unhandled exception during alert action execution: {e}")
            sys.exit(1)
    else:
        print(
            "FATAL: cert_alert_webhook must be invoked with --execute",
            file=sys.stderr,
        )
        sys.exit(1)
