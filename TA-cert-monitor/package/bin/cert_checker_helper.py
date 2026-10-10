#!/usr/bin/env python3
"""
Splunk Add-on for SSL/TLS Certificate Monitoring (TA-cert-monitor)
Modular Input: cert_checker_helper
Version: 2.1.8
Description: Gathers certificate telemetry, validates validity lifecycles, parses Subject
Alternative Names (SAN), and optionally audits legacy TLS protocol support.
"""

import datetime
import json
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

logger = log.Logs().get_logger("ta_cert_monitor")


def update_log_level_from_settings(session_key: str, app_name: str = ADDON_NAME):
    """
    Reads the loglevel configured in UCC's Configuration -> Logging tab
    using solnlib.conf_manager and applies it to the active logger.
    """
    if not session_key:
        return

    try:
        cfm = conf_manager.ConfManager(session_key, app_name)
        logging_stanza = cfm.get_conf(CONF_FILE).get("logging")
        level_name = logging_stanza.get("loglevel", "INFO").upper()

        log.Logs().set_context(log_level=level_name)
        logger.setLevel(level_name)

    except Exception as e:
        logger.debug(f"Unable to read loglevel from settings conf: {e}")


def validate_input(definition: smi.ValidationDefinition):
    """
    Validates form parameters submitted in UCC Splunk Web.
    Raises ValueError to display user-facing validation errors in the UI modal.
    """
    params = definition.parameters

    target_host = params.get("target_host", "").strip()
    port = params.get("port")
    timeout = params.get("timeout")

    if not target_host:
        raise ValueError("Target Host / IP is required.")

    if port is not None:
        try:
            port_val = int(port)
            if not (1 <= port_val <= 65535):
                raise ValueError("Port must be an integer between 1 and 65535.")
        except ValueError:
            raise ValueError("Port must be a valid numeric integer.")

    if timeout is not None:
        try:
            timeout_val = float(timeout)
            if timeout_val <= 0:
                raise ValueError("Timeout must be a positive number.")
        except ValueError:
            raise ValueError("Timeout must be a valid numeric value.")


def get_proxy_url(session_key: str, app_name: str = ADDON_NAME) -> str | None:
    """
    Retrieves proxy settings from UCC's Configuration -> Proxy tab
    and constructs a standard proxy URL (e.g. http://user:pass@proxy.corp:8080).
    Returns None if proxy is disabled or not configured.
    """
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

        # Build credentials string if authentication is configured
        auth = ""
        if username and password:
            user_enc = urllib.parse.quote(username, safe="")
            pass_enc = urllib.parse.quote(password, safe="")
            auth = f"{user_enc}:{pass_enc}@"

        # Strip any existing scheme from host if provided
        if "://" in host:
            host = host.split("://", 1)[-1]

        return f"{proxy_type}://{auth}{host}:{port}"

    except Exception as e:
        logger.debug(f"Unable to resolve proxy URL: {e}")
        return None


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
    target_host: str,
    port: int = 443,
    sni: str | None = None,
    verify_cert: bool = True,
    timeout: int | float = 10,
    audit_legacy_protocols: bool = False,
    proxy_url: str | None = None,
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
                leaf_cert=x509_cert,
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


def stream_events(inputs: smi.InputDefinition, ew: smi.EventWriter):
    """
    Processes scheduled polling executions for each configured input stanza.
    """
    session_key = inputs.metadata.get("session_key")
    update_log_level_from_settings(session_key)
    proxy_url = get_proxy_url(session_key)

    if proxy_url:
        logger.info(f"Active proxy detected: {proxy_url.split('@')[-1]}")

    for input_name, input_item in inputs.inputs.items():
        stanza_title = (
            input_name.split("://")[-1] if "://" in input_name else input_name
        )

        target_host = input_item.get("target_host", "").strip()
        port = int(input_item.get("port", 443))
        sni = input_item.get("sni") or target_host
        timeout = float(input_item.get("timeout", 10))
        verify_cert = str(input_item.get("verify_cert", "false")).lower() in (
            "true",
            "1",
        )
        audit_legacy = str(
            input_item.get("audit_legacy_protocols", "false")
        ).lower() in ("true", "1")

        index = input_item.get("index", "ssl_cert")
        sourcetype = input_item.get("sourcetype", "cert:ssl:json")

        msg = f"Auditing endpoint='{target_host}:{port}' (SNI: '{sni}') for stanza='{stanza_title}'"
        ew.log(smi.EventWriter.INFO, msg)
        logger.info(msg)

        try:
            payload = check_endpoint_certificate(
                target_host=target_host,
                port=port,
                sni=sni,
                timeout=timeout,
                verify_cert=verify_cert,
                audit_legacy_protocols=audit_legacy,
                proxy_url=proxy_url,
            )

            event = smi.Event(
                data=json.dumps(payload),
                stanza=input_name,
                time=time.time(),
                index=index,
                sourcetype=sourcetype,
                done=True,
                unbroken=True,
            )
            ew.write_event(event)

            logger.info(
                f"Successfully ingested certificate audit for {target_host}:{port}"
            )

        except Exception as e:
            err_msg = f"Failed to probe certificate for {target_host}:{port} - {str(e)}"
            ew.log(smi.EventWriter.ERROR, err_msg)
            logger.error(err_msg, exc_info=True)

            error_payload = {
                "dest": target_host,
                "dest_port": port,
                "sni": sni,
                "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "status": "CONNECTION_ERROR",
                "error": str(e),
                "days_remaining": None,
                "negotiated_tls_version": None,
                "cipher": None,
                "is_self_signed": False,
                "revocation_status": "ERROR",
                "revocation_reason": str(e),
                "legacy_protocols_supported": [],
                "has_legacy_tls": False,
            }
            error_event = smi.Event(
                data=json.dumps(error_payload),
                stanza=input_name,
                time=time.time(),
                index=index,
                sourcetype=sourcetype,
                done=True,
                unbroken=True,
            )
            ew.write_event(error_event)
