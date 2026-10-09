#!/usr/bin/env python3
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

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(BIN_DIR)
LIB_DIRS = [
    os.path.join(APP_DIR, "lib"),
    os.path.join(BIN_DIR, "lib"),
]

for lib_dir in LIB_DIRS:
    if os.path.isdir(lib_dir) and lib_dir not in sys.path:
        sys.path.insert(0, lib_dir)

from solnlib import log

logger = log.Logs().get_logger("ta_cert_monitor_alert_webhook")


def read_search_results(results_file):
    """
    Reads search results from Splunk's passed gzipped results file.
    Returns a list of parsed row dictionaries.
    """
    if not results_file or not os.path.exists(results_file):
        return []

    records = []
    try:
        import csv

        with gzip.open(
            results_file, mode="rt", encoding="utf-8", errors="replace"
        ) as gz_file:
            reader = csv.DictReader(gz_file)
            for row in reader:
                records.append(row)
    except Exception as exc:
        logger.warning(f"Could not parse results_file as gzipped CSV: {exc}")
        try:
            with open(results_file, mode="r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(row)
        except Exception as fallback_exc:
            logger.error(f"Failed to read results file: {fallback_exc}")

    return records


def send_webhook(url, payload, timeout=15):
    """
    Sends JSON payload to the specified HTTPS endpoint with strict TLS verification.
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme.lower() != "https":
        raise ValueError(
            f"Insecure protocol rejected: '{parsed_url.scheme}'. Only HTTPS is permitted."
        )

    data_bytes = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Splunk-TA-cert-monitor-Webhook/2.1.8",
        "Accept": "application/json",
    }

    # Enforce strict TLS 1.2+ verification with system CA trust store
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=ssl_context
        ) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8", errors="replace")
            logger.info(
                f"Successfully posted alert to webhook. HTTP Status: {status_code}"
            )
            return status_code, response_body
    except urllib.error.HTTPError as http_err:
        logger.error(
            f"HTTP error posting to webhook: {http_err.code} - {http_err.reason}"
        )
        raise
    except urllib.error.URLError as url_err:
        logger.error(f"Network error posting to webhook: {url_err.reason}")
        raise


def main():
    logger.info("Initializing cert_alert_webhook action...")

    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        logger.error("Modular alert script must be invoked with '--execute'")
        sys.exit(1)

    try:
        raw_payload = sys.stdin.read()
        if not raw_payload.strip():
            logger.error("No configuration payload received on STDIN.")
            sys.exit(2)

        config = json.loads(raw_payload)
    except Exception as exc:
        logger.error(f"Failed to parse alert action configuration from STDIN: {exc}")
        sys.exit(3)

    configuration = config.get("configuration", {})
    webhook_url = configuration.get("webhook_url")
    severity = configuration.get("severity", "high")
    results_file = config.get("results_file")
    search_name = config.get("search_name", "SSL Certificate Alert")
    app_name = config.get("app", "TA-cert-monitor")

    if not webhook_url:
        logger.error("Execution failed: 'webhook_url' parameter is missing or empty.")
        sys.exit(4)

    results = read_search_results(results_file)

    outbound_payload = {
        "event_type": "ssl_certificate_alert",
        "search_name": search_name,
        "app": app_name,
        "severity": severity,
        "result_count": len(results),
        "results": results[:50],
        "server_uri": config.get("server_uri", ""),
        "owner": config.get("owner", ""),
    }

    try:
        send_webhook(webhook_url, outbound_payload)
    except Exception as exc:
        logger.error(f"Webhook dispatch failed: {exc}")
        sys.exit(5)

    logger.info("cert_alert_webhook finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
