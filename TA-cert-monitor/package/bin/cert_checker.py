#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Splunk Add-on for SSL/TLS Certificate Monitoring (TA-cert-monitor)
Modular Input: cert_checker
Version: 2.0.0
"""

import datetime
import json
import logging
import os
import socket
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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPCertStatus, OCSPResponseStatus
from solnlib import conf_manager, log
from splunklib import modularinput as smi

ADDON_NAME = "TA-cert-monitor"
CONF_FILE = "ta_cert_monitor_settings"


def get_ucc_settings(session_key: str):
    """Retrieve logging and proxy configurations from UCC-generated conf."""
    settings = {
        "loglevel": "INFO",
        "proxy_enabled": False,
        "proxy_url": None,
        "proxy_port": "8080",
        "proxy_username": None,
        "proxy_password": None,
    }
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{CONF_FILE}",
        )
        conf = cfm.get_conf(CONF_FILE)
        logging_stanza = conf.get("logging")
        if logging_stanza:
            settings["loglevel"] = logging_stanza.get("loglevel", "INFO")

        proxy_stanza = conf.get("proxy")
        if proxy_stanza:
            settings["proxy_enabled"] = str(
                proxy_stanza.get("proxy_enabled", "0")
            ).lower() in ("1", "true")
            settings["proxy_url"] = proxy_stanza.get("proxy_url")
            settings["proxy_port"] = proxy_stanza.get("proxy_port", "8080")
            settings["proxy_username"] = proxy_stanza.get("proxy_username")
            settings["proxy_password"] = proxy_stanza.get("proxy_password")
    except Exception:
        # Fall back to sensible defaults if running in test context or initial load
        pass
    return settings


def logger_for_input(loglevel, input_name: str = "modinput") -> logging.Logger:
    """Initialize structured logging using solnlib."""
    logger = log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")
    log.Logs().set_context(logger=logger, log_level=loglevel)
    return logger


def get_account_api_key(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{ADDON_NAME}_account",
    )
    account_conf_file = cfm.get_conf(f"{ADDON_NAME}_account")
    return account_conf_file.get(account_name).get("api_key")


def check_ocsp_status(leaf_cert, issuer_cert=None, proxy_url=None, timeout=5):
    """Query OCSP responder for revocation status."""
    try:
        try:
            aia = leaf_cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
        except x509.ExtensionNotFound:
            return {
                "revocation_status": "NOT_CHECKED",
                "reason": "No AIA extension in certificate",
            }

        # Extract OCSP server URLs
        ocsp_servers = [
            desc.access_location.value
            for desc in aia
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
            and isinstance(desc.access_location.value, str)
        ]
        if not ocsp_servers:
            return {"revocation_status": "NOT_CHECKED", "reason": "No OCSP URI in AIA"}

        handlers = []
        if proxy_url:
            handlers.append(
                urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            )
        opener = urllib.request.build_opener(*handlers)

        # If issuer cert wasn't provided, attempt to fetch it from caIssuers in AIA
        if issuer_cert is None:
            ca_issuers = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS
                and isinstance(desc.access_location.value, str)
            ]
            if ca_issuers:
                try:
                    req_issuer = urllib.request.Request(
                        ca_issuers[0], headers={"User-Agent": "Splunk-TA-cert-monitor"}
                    )
                    with opener.open(req_issuer, timeout=timeout) as resp:
                        issuer_bytes = resp.read()
                        try:
                            issuer_cert = x509.load_der_x509_certificate(
                                issuer_bytes, default_backend()
                            )
                        except Exception:
                            issuer_cert = x509.load_pem_x509_certificate(
                                issuer_bytes, default_backend()
                            )
                except Exception:
                    issuer_cert = None

        if issuer_cert is None:
            return {
                "revocation_status": "NOT_CHECKED",
                "reason": "Issuer CA certificate unavailable for OCSP verification",
            }

        # Build OCSP Request
        ocsp_url = ocsp_servers[0]
        builder = x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(leaf_cert, issuer_cert, hashes.SHA1())
        req = builder.build()
        req_data = req.public_bytes(serialization.Encoding.DER)

        headers = {"Content-Type": "application/ocsp-request"}
        request = urllib.request.Request(
            ocsp_url, data=req_data, headers=headers, method="POST"
        )

        with opener.open(request, timeout=timeout) as response:
            if response.status == 200:
                ocsp_resp = x509.ocsp.load_der_ocsp_response(response.read())
                if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
                    if ocsp_resp.certificate_status == OCSPCertStatus.GOOD:
                        return {
                            "revocation_status": "GOOD",
                            "reason": "Certificate is valid according to OCSP",
                        }
                    elif ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
                        revoked_reason = (
                            ocsp_resp.revocation_reason.name
                            if ocsp_resp.revocation_reason
                            else "UNSPECIFIED"
                        )
                        return {
                            "revocation_status": "REVOKED",
                            "reason": revoked_reason,
                        }
                    else:
                        return {
                            "revocation_status": "UNKNOWN",
                            "reason": "OCSP responder returned status UNKNOWN",
                        }
        return {
            "revocation_status": "ERROR",
            "reason": f"Non-200 response ({response.status}) from OCSP responder",
        }
    except Exception as e:
        return {"revocation_status": "ERROR", "reason": str(e)}


class CertChecker(smi.Script):
    def get_scheme(self):
        scheme = smi.Scheme("Certificate Endpoint")
        scheme.description = "Audits SSL/TLS certificates, expiry dates, trust chains, and OCSP revocation."
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                "target_host",
                title="Target Host / IP",
                description="FQDN or IP address of the TLS endpoint",
                data_type=smi.Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "port",
                title="Port",
                description="Target TCP port number (1-65535, default 443)",
                data_type=smi.Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "sni",
                title="SNI",
                description="TLS SNI hostname override (defaults to target_host if omitted)",
                data_type=smi.Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "timeout",
                title="Connection Timeout",
                description="TCP handshake and TLS negotiation timeout in seconds (5-300, default 10)",
                data_type=smi.Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "verify_cert",
                title="Strict Root Verification",
                description="Validate certificate chain against system/local CA trust store (true/false)",
                data_type=smi.Argument.data_type_boolean,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition):
        """External validation invoked by Splunk Web / REST before saving input stanzas."""
        params = definition.parameters

        # 1. Validate target_host
        target_host = params.get("target_host", "").strip()
        if not target_host:
            raise ValueError("Target Host / IP cannot be empty.")
        if len(target_host) > 255:
            raise ValueError("Target Host / IP cannot exceed 255 characters.")

        # 2. Validate port
        port = params.get("port")
        if port is not None and str(port).strip():
            try:
                port_num = int(port)
                if port_num < 1 or port_num > 65535:
                    raise ValueError("Port must be an integer between 1 and 65535.")
            except ValueError:
                raise ValueError(
                    f"Invalid port value '{port}': Must be an integer between 1 and 65535."
                )

        # 3. Validate timeout
        timeout = params.get("timeout")
        if timeout is not None and str(timeout).strip():
            try:
                timeout_val = int(timeout)
                if timeout_val < 1 or timeout_val > 300:
                    raise ValueError(
                        "Connection Timeout must be an integer between 1 and 300 seconds."
                    )
            except ValueError:
                raise ValueError(
                    f"Invalid timeout value '{timeout}': Must be an integer between 1 and 300."
                )

        # 4. Validate SNI
        sni = params.get("sni", "").strip()
        if sni and len(sni) > 255:
            raise ValueError("SNI value cannot exceed 255 characters.")

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        # inputs.inputs is a Python dictionary object like:
        # {
        #   "demo_input://<input_name>": {
        #     "account": "<account_name>",
        #     "disabled": "0",
        #     "host": "$decideOnStartup",
        #     "index": "<index_name>",
        #     "interval": "<interval_value>",
        #     "python.version": "python3",
        #   },
        # }
        session_key = self._input_definition.metadata.get("session_key")
        ucc_settings = get_ucc_settings(session_key)
        logger = logger_for_input(ucc_settings.get("loglevel"))

        # Construct proxy URI if enabled
        proxy_conn_str = None
        if ucc_settings.get("proxy_enabled") and ucc_settings.get("proxy_url"):
            p_user = ucc_settings.get("proxy_username")
            p_pass = ucc_settings.get("proxy_password")
            p_host = ucc_settings.get("proxy_url")
            p_port = ucc_settings.get("proxy_port", "8080")
            if p_user and p_pass:
                proxy_conn_str = f"http://{urllib.parse.quote(p_user)}:{urllib.parse.quote(p_pass)}@{p_host}:{p_port}"
            else:
                proxy_conn_str = f"http://{p_host}:{p_port}"

        now_utc = datetime.datetime.now(datetime.timezone.utc)

        for input_name, input_item in inputs.inputs.items():
            target_host = input_item.get("target_host", "").strip()

            raw_port = input_item.get("port")
            port = int(raw_port) if raw_port and str(raw_port).strip() else 443

            sni = input_item.get("sni") or target_host

            raw_timeout = input_item.get("timeout")
            timeout = (
                int(raw_timeout) if raw_timeout and str(raw_timeout).strip() else 10
            )

            verify_cert = str(input_item.get("verify_cert", "false")).lower() in (
                "1",
                "true",
            )
            index = input_item.get("index", "ssl_cert")

            logger.info(
                f"Starting certificate probe for stanza={input_name} target={target_host}:{port} sni={sni}"
            )

            record = {
                "dest": target_host,
                "dest_port": port,
                "sni": sni,
                "status": "UNKNOWN",
                "ssl_version": None,
                "ssl_cipher": None,
            }

            try:
                # Prepare SSL Context
                if verify_cert:
                    ctx = ssl.create_default_context()
                else:
                    ctx = ssl._create_unverified_context()

                # Acquire raw DER peer certificate and negotiated parameters
                with socket.create_connection(
                    (target_host, port), timeout=timeout
                ) as sock:
                    with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            record["ssl_cipher"] = cipher_info[0]
                            record["ssl_version"] = cipher_info[1]

                if not der_cert:
                    raise ValueError(
                        "Handshake completed but peer certificate was empty"
                    )

                # Parse certificate with cryptography.x509
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # Subject and Issuer
                record["subject"] = cert.subject.rfc4514_string()
                record["issuer"] = cert.issuer.rfc4514_string()

                subject_cn = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )
                record["subject_cn"] = subject_cn[0].value if subject_cn else None

                issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                record["issuer_cn"] = issuer_cn[0].value if issuer_cn else None

                # SAN (Subject Alternative Names)
                try:
                    san_ext = cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    ).value
                    record["san"] = san_ext.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    record["san"] = []

                # Serial Number and Fingerprints
                record["serial_number"] = hex(cert.serial_number)[2:].upper()
                record["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()

                # Validity and Expiration Calculation
                valid_from = cert.not_valid_before_utc
                valid_to = cert.not_valid_after_utc
                record["valid_from"] = valid_from.strftime("%Y-%m-%d %H:%M:%S UTC")
                record["valid_to"] = valid_to.strftime("%Y-%m-%d %H:%M:%S UTC")

                delta = valid_to - now_utc
                days_left = round(delta.total_seconds() / 86400.0, 2)
                record["days_remaining"] = days_left

                # Self-Signed Evaluation
                is_self_signed = cert.subject == cert.issuer
                record["is_self_signed"] = is_self_signed

                # Trust and Life-Cycle Status
                if days_left <= 0:
                    record["status"] = "EXPIRED"
                elif days_left <= 15:
                    record["status"] = "EXPIRING_CRITICAL"
                elif days_left <= 30:
                    record["status"] = "EXPIRING_WARNING"
                else:
                    record["status"] = "VALID"

                sig_oid = cert.signature_algorithm_oid
                record["signature_algorithm"] = getattr(
                    sig_oid, "_name", sig_oid.dotted_string
                )

                record["revocation_status"] = "NOT_EVALUATED"
                record["revocation_reason"] = None

                # Perform OCSP probe if not self-signed
                if not is_self_signed:
                    ocsp_result = check_ocsp_status(
                        cert,
                        issuer_cert=None,
                        proxy_url=proxy_conn_str,
                        timeout=timeout,
                    )
                    record["revocation_status"] = ocsp_result.get("revocation_status")
                    record["revocation_reason"] = ocsp_result.get("reason")
                    if record["revocation_status"] == "REVOKED":
                        record["status"] = "REVOKED"

            except Exception as e:
                logger.error(
                    f"Probe error on stanza={input_name} target={target_host}:{port} - {str(e)}"
                )
                record["status"] = "CONNECTION_ERROR"
                record["error_message"] = str(e)

            # Stream JSON Event to Splunk
            event = smi.Event()
            event.stanza = input_name
            event.index = index
            event.sourcetype = "cert:ssl:json"
            event.source = "cert_checker"
            event.data = json.dumps(record)
            ew.write_event(event)

            logger.info(
                f"Completed probe for stanza={input_name}. Status: {record['status']}"
            )


if __name__ == "__main__":
    sys.exit(CertChecker().run(sys.argv))
