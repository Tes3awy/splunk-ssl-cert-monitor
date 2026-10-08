#!/usr/bin/env python3
"""
Splunk Add-on for SSL/TLS Certificate Monitoring (TA-cert-monitor)
Modular Input: cert_checker
Version: 2.1.5
Description: Gathers certificate telemetry, validates validity lifecycles, parses Subject
Alternative Names (SAN), and optionally audits legacy TLS protocol support.
"""

import datetime
import json
import logging
import os
import socket
import ssl
import sys
import time
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


def probe_legacy_tls_protocols(host, port, sni=None, timeout=3.0):
    """Actively probes whether the endpoint accepts deprecated TLS versions."""
    legacy_accepted = []
    target_sni = sni if sni else host

    # Probe TLS 1.0
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1"):
        try:
            ctx_10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_10.check_hostname = False
            ctx_10.verify_mode = ssl.CERT_NONE
            ctx_10.minimum_version = ssl.TLSVersion.TLSv1
            ctx_10.maximum_version = ssl.TLSVersion.TLSv1
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_10.wrap_socket(sock, server_hostname=target_sni):
                    legacy_accepted.append("TLSv1.0")
        except Exception:
            pass

    # Probe TLS 1.1
    if hasattr(ssl, "TLSVersion") and hasattr(ssl.TLSVersion, "TLSv1_1"):
        try:
            ctx_11 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_11.check_hostname = False
            ctx_11.verify_mode = ssl.CERT_NONE
            ctx_11.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx_11.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_11.wrap_socket(sock, server_hostname=target_sni):
                    legacy_accepted.append("TLSv1.1")
        except Exception:
            pass

    return legacy_accepted


def check_endpoint_certificate(
    target_host,
    port=443,
    sni=None,
    verify_cert=True,
    timeout=10,
    audit_legacy_protocols=False,
    proxy_url=None,
):
    """Establishes a TLS session to retrieve and evaluate certificate telemetry."""
    target_sni = sni if sni else target_host
    now = datetime.datetime.now(datetime.timezone.utc)

    record = {
        "dest": target_host,
        "dest_port": int(port),
        "sni": target_sni,
        "time": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": "UNKNOWN",
        "days_remaining": None,
        "san_list": [],
        "san_count": 0,
        "has_wildcard_san": False,
        "negotiated_tls_version": None,
        "cipher": None,
        "signature_algorithm": None,
        "fingerprint_sha256": None,
        "issuer": None,
        "issuer_cn": None,
        "subject": None,
        "subject_cn": None,
        "serial_number": None,
        "valid_from": None,
        "valid_to": None,
        "error": None,
    }

    # Setup primary SSL context
    ctx = ssl.create_default_context()
    if not verify_cert:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection(
                (target_host, int(port)), timeout=float(timeout)
            ) as sock,
            ctx.wrap_socket(sock, server_hostname=target_sni) as ssock,
        ):
            record["negotiated_tls_version"] = ssock.version()
            cipher_info = ssock.cipher()
            if cipher_info:
                record["cipher"] = cipher_info[0]

            # Always fetch binary cert and use cryptography for uniform parsing
            der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            raise ValueError("Handshake completed but peer certificate was empty")

        # Parse certificate with cryptography.x509
        x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # Subject and Issuer
        record["subject"] = x509_cert.subject.rfc4514_string()
        record["issuer"] = x509_cert.issuer.rfc4514_string()

        subject_cn = x509_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        record["subject_cn"] = subject_cn[0].value if subject_cn else None

        issuer_cn = x509_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        record["issuer_cn"] = issuer_cn[0].value if issuer_cn else None

        # SAN (Subject Alternative Names)
        try:
            san_ext = x509_cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            record["san_list"] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            record["san_list"] = []

        record["san_count"] = len(record["san_list"])
        record["has_wildcard_san"] = any(s.startswith("*.") for s in record["san_list"])

        # Serial Number and Fingerprints
        record["serial_number"] = f"{x509_cert.serial_number:X}"
        record["fingerprint_sha256"] = x509_cert.fingerprint(hashes.SHA256()).hex()
        record["signature_algorithm"] = (
            x509_cert.signature_hash_algorithm.name
            if x509_cert.signature_hash_algorithm
            else "unknown"
        )

        # Validity and Expiration Calculation
        not_after = (
            x509_cert.not_valid_after_utc
            if hasattr(x509_cert, "not_valid_after_utc")
            else x509_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        )
        not_before = (
            x509_cert.not_valid_before_utc
            if hasattr(x509_cert, "not_valid_before_utc")
            else x509_cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        )

        record["valid_to"] = not_after.strftime("%Y-%m-%d %H:%M:%S UTC")
        record["valid_from"] = not_before.strftime("%Y-%m-%d %H:%M:%S UTC")

        days_left = round((not_after - now).total_seconds() / 86400.0, 2)
        record["days_remaining"] = days_left
        if days_left < 0:
            record["status"] = "EXPIRED"
        elif days_left <= 15:
            record["status"] = "EXPIRING_CRITICAL"
        elif days_left <= 30:
            record["status"] = "EXPIRING_WARNING"
        else:
            record["status"] = "VALID"

        # Self-Signed Evaluation
        is_self_signed = x509_cert.subject == x509_cert.issuer
        record["is_self_signed"] = is_self_signed

        record["revocation_status"] = "NOT_EVALUATED"
        record["revocation_reason"] = None

        # Perform OCSP probe if not self-signed
        if not is_self_signed:
            ocsp_result = check_ocsp_status(
                x509_cert,
                issuer_cert=None,
                proxy_url=proxy_url,
                timeout=timeout,
            )
            record["revocation_status"] = ocsp_result.get("revocation_status")
            record["revocation_reason"] = ocsp_result.get("reason")
            if record["revocation_status"] == "REVOKED":
                record["status"] = "REVOKED"

    except ssl.SSLCertVerificationError as e:
        record["status"] = "UNTRUSTED_OR_EXPIRED"
        record["error"] = f"SSL Certificate Verification Error: {e!s}"
    except socket.timeout:
        record["status"] = "TIMEOUT"
        record["error"] = f"Connection timed out after {timeout} seconds."
    except ConnectionRefusedError:
        record["status"] = "CONNECTION_REFUSED"
        record["error"] = f"Connection refused on port {port}."
    except Exception as e:
        record["status"] = "ERROR"
        record["error"] = f"Unexpected connection error: {e!s}"

    # Optional: Active probe for legacy TLS (TLS 1.0 / 1.1)
    if audit_legacy_protocols:
        legacy_supported = probe_legacy_tls_protocols(
            host=target_host,
            port=port,
            sni=target_sni,
            timeout=min(3.0, float(timeout)),
        )
        record["legacy_protocols_supported"] = legacy_supported
        record["has_legacy_tls"] = len(legacy_supported) > 0
        record["security_compliance_status"] = (
            "NON_COMPLIANT" if record["has_legacy_tls"] else "COMPLIANT"
        )
    else:
        record["legacy_protocols_supported"] = []
        record["has_legacy_tls"] = False
        record["security_compliance_status"] = "AUDIT_DISABLED"

    return record


class CertChecker(smi.Script):
    def get_scheme(self):
        scheme = smi.Scheme("Certificate Endpoint")
        scheme.description = "Collect SSL/TLS certificate attributes, lifecycle status, SAN domains, and audit legacy protocols."
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                name="target_host",
                title="Target Host / IP",
                description="FQDN or IP address of the TLS endpoint",
                data_type=smi.Argument.data_type_string,
                required_on_create=True,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                name="port",
                title="Port",
                description="Target TCP port number (1-65535, default 443)",
                data_type=smi.Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                name="sni",
                title="SNI",
                description="TLS SNI hostname override (defaults to target_host if omitted)",
                data_type=smi.Argument.data_type_string,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                name="timeout",
                title="Connection Timeout",
                description="TCP handshake and TLS negotiation timeout in seconds (5-300, default 10)",
                data_type=smi.Argument.data_type_number,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                name="verify_cert",
                title="Strict Root Verification",
                description="Validate certificate chain against system/local CA trust store (true/false)",
                data_type=smi.Argument.data_type_boolean,
                required_on_create=False,
                required_on_edit=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                name="audit_legacy_protocols",
                title="Audit Legacy Protocols",
                description="Probe for TLS 1.0/1.1 acceptance (true/false)",
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
        session_key = inputs.metadata.get("session_key")
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
            audit_legacy = str(
                input_item.get("audit_legacy_protocols", "false")
            ).lower() in ("true", "1", "yes")

            index = input_item.get("index", "ssl_cert")

            logger.info(
                f"Starting certificate probe for stanza={input_name} target={target_host}:{port} sni={sni}"
            )

            record = check_endpoint_certificate(
                target_host=target_host,
                port=port,
                sni=sni,
                verify_cert=verify_cert,
                timeout=timeout,
                audit_legacy_protocols=audit_legacy,
                proxy_url=proxy_conn_str,
            )

            # Stream JSON Event to Splunk
            event = smi.Event()
            event.stanza = input_name
            event.index = index
            event.source = f"cert_checker://{input_name}"
            event.sourcetype = "cert:ssl:json"
            event.data = json.dumps(record)
            event.time = str(int(time.time()))
            ew.write_event(event)

            logger.info(
                f"Completed probe for stanza={input_name}. Status: {record.get('status', 'UNKNOWN')}"
            )


if __name__ == "__main__":
    sys.exit(CertChecker().run(sys.argv))
