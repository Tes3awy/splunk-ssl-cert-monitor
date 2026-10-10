#!/usr/bin/env python3
"""
Splunk Modular Alert Action: SSL Expiration Webhook
Dispatches structured search results for expiring certificates to an external webhook.
Version: 2.1.8
"""

import csv
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

from solnlib import conf_manager, log

ADDON_NAME = "TA-cert-monitor"
CONF_FILE = "ta_cert_monitor_settings"

logger = log.Logs().get_logger("ta_cert_monitor_alert_webhook")


def update_log_level_from_settings(session_key: str, app_name: str = ADDON_NAME):
    """Syncs logging level with UCC's Configuration -> Logging tab."""
    if not session_key:
        return
    try:
        cfm = conf_manager.ConfManager(session_key, app_name)
        settings = cfm.get_conf(CONF_FILE)
        logging_stanza = settings.get("logging")
        level_name = logging_stanza.get("loglevel", "INFO").upper()

        log.Logs().set_context(log_level=level_name)
        logger.setLevel(level_name)
    except Exception as exc:
        logger.debug(f"Unable to read loglevel from settings conf: {exc}")


def get_proxy_url(session_key: str, app_name: str = ADDON_NAME) -> str | None:
    """Retrieves proxy settings from UCC's Configuration -> Proxy tab."""
    if not session_key:
        return None
    try:
        cfm = conf_manager.ConfManager(session_key, app_name)
        proxy_stanza = cfm.get_conf(CONF_FILE).get("proxy")
        if not proxy_stanza:
            return None

        proxy_enabled = str(proxy_stanza.get("proxy_enabled", "0")).lower() in (
            "1",
            "true",
        )
        if not proxy_enabled:
            return None

        host = proxy_stanza.get("proxy_url", "").strip()
        if not host:
            return None

        port = proxy_stanza.get("proxy_port", "8080")
        proxy_type = proxy_stanza.get("proxy_type", "http").lower()
        username = proxy_stanza.get("proxy_username", "").strip()
        password = proxy_stanza.get("proxy_password", "").strip()

        auth = ""
        if username and password:
            user_enc = urllib.parse.quote(username, safe="")
            pass_enc = urllib.parse.quote(password, safe="")
            auth = f"{user_enc}:{pass_enc}@"

        if "://" in host:
            host = host.split("://", 1)[-1]

        return f"{proxy_type}://{auth}{host}:{port}"
    except Exception as exc:
        logger.debug(f"Unable to resolve proxy URL: {exc}")
        return None


def read_search_results(results_file):
    """
    Reads search results from Splunk's passed results file (gzipped CSV or plain CSV).
    Returns a list of parsed row dictionaries.
    """
    if not results_file or not os.path.exists(results_file):
        return []

    records = []
    try:
        with gzip.open(
            results_file, mode="rt", encoding="utf-8", errors="replace"
        ) as gz_file:
            reader = csv.DictReader(gz_file)
            for row in reader:
                records.append(row)
    except Exception as exc:
        logger.debug(f"Falling back to uncompressed CSV parser: {exc}")
        try:
            with open(results_file, mode="r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    records.append(row)
        except Exception as fallback_exc:
            logger.error(f"Failed to read results file: {fallback_exc}")

    return records


def send_webhook(url, payload, auth_token=None, proxy_url=None, timeout=15):
    """
    Sends JSON payload to the specified HTTPS endpoint with strict TLS verification
    and optional proxy support.
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme.lower() != "https":
        raise ValueError(
            f"Insecure protocol rejected: '{parsed_url.scheme}'. Only HTTPS is permitted."
        )

    data_bytes = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "Splunk-TA-cert-monitor-Webhook/2.2.0",
        "Accept": "application/json",
    }

    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token.strip()}"

    # Enforce TLS 1.2+
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

    handlers = [urllib.request.HTTPSHandler(context=ssl_context)]
    if proxy_url:
        logger.debug("Routing webhook call through configured proxy")
        handlers.append(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )

    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")

    try:
        with opener.open(req, timeout=timeout) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8", errors="replace")
            logger.info(
                f"Successfully posted alert to webhook. HTTP Status: {status_code}"
            )
            return status_code, response_body
    except urllib.error.HTTPError as http_err:
        err_body = http_err.read().decode("utf-8", errors="replace")
        logger.error(
            f"HTTP error posting to webhook ({http_err.code} {http_err.reason}): {err_body}"
        )
        raise
    except urllib.error.URLError as url_err:
        logger.error(f"Network error posting to webhook: {url_err.reason}")
        raise


def main():
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

    session_key = config.get("session_key")
    update_log_level_from_settings(session_key)

    configuration = config.get("configuration", {})
    webhook_url = configuration.get("webhook_url") or configuration.get(
        "param.webhook_url"
    )
    auth_token = configuration.get("auth_token") or configuration.get(
        "param.auth_token"
    )
    severity = (
        configuration.get("severity") or configuration.get("param.severity") or "high"
    )
    results_file = config.get("results_file")
    search_name = config.get("search_name", "SSL Certificate Alert")
    app_name = config.get("app", ADDON_NAME)

    if not webhook_url:
        logger.error("Execution failed: 'webhook_url' parameter is missing or empty.")
        sys.exit(4)

    proxy_url = get_proxy_url(session_key)
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
        send_webhook(
            url=webhook_url,
            payload=outbound_payload,
            auth_token=auth_token,
            proxy_url=proxy_url,
            timeout=15,
        )
    except Exception as exc:
        logger.error(f"Webhook dispatch failed: {exc}")
        sys.exit(5)

    logger.info("cert_alert_webhook finished successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
