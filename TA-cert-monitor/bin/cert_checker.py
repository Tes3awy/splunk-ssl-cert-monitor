#!/usr/bin/env python3
"""
Splunk Modular Input: SSL/TLS Certificate Monitor
Collects certificate expiration, issuer, subject, SANs, and cipher details via SNI.
"""

import csv
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_response,
)

# 1. Resolve and inject vendored 'lib' BEFORE importing third-party packages
BIND_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(BIND_DIR, "lib")
if os.path.exists(LIB_DIR) and LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

# 2. Structured logging initialization with graceful fallback
try:
    from solnlib import log

    logger = log.Logs().get_logger("ta_cert_monitor")
except ImportError:
    import logging

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    logger = logging.getLogger("ta_cert_monitor")


def log_err(message):
    """Logs errors to both structured logger and splunkd.log standard channel."""
    logger.error(message)
    sys.stderr.write(f"ERROR cert_checker: {message}\n")
    sys.stderr.flush()


def is_prohibited_ip(host_str):
    """
    Blocks direct connection attempts to cloud metadata IP addresses
    and IPv4/IPv6 loopback targets to prevent SSRF abuse.
    """
    try:
        ip = ipaddress.ip_address(host_str)
        if ip.is_link_local or ip.is_loopback:
            return (
                True,
                "Access to link-local, loopback, and cloud metadata addresses is prohibited.",
            )
    except ValueError:
        # Target is a hostname, not a raw IP address
        pass
    return False, None


def parse_dn(dn_tuple):
    """Converts standard getpeercert() RDN tuple structure into a flat dict."""
    dn_dict = {}
    if not dn_tuple:
        return dn_dict
    for rdn in dn_tuple:
        for key, value in rdn:
            dn_dict[key] = value
    return dn_dict


def parse_ssl_date(date_str):
    """Parses OpenSSL date format ('Mon DD HH:MM:SS YYYY GMT') into UTC datetime."""
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


def format_cert_dict(cert, now_utc):
    """Parses a decoded OpenSSL cert dictionary into standard schema fields."""
    if not cert:
        return None

    subject_dict = parse_dn(cert.get("subject", ()))
    issuer_dict = parse_dn(cert.get("issuer", ()))
    sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

    not_before = parse_ssl_date(cert["notBefore"])
    not_after = parse_ssl_date(cert["notAfter"])
    days_remaining = (not_after - now_utc).total_seconds() / 86400.0

    return {
        "subject_cn": subject_dict.get("commonName"),
        "subject_org": subject_dict.get("organizationName"),
        "subject_alt_names": sans,
        "issuer_cn": issuer_dict.get("commonName"),
        "issuer_org": issuer_dict.get("organizationName"),
        "serial_number": cert.get("serialNumber"),
        "valid_from": not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_to": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_remaining": round(days_remaining, 2),
        "is_expired": days_remaining <= 0,
        "is_self_signed": subject_dict == issuer_dict,
    }


def parse_der_bytes(der_bytes):
    """Decodes raw DER binary certificate using Python's OpenSSL helper."""
    tf_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(der_bytes)
            tf.flush()
            tf_path = tf.name
        return ssl._ssl._test_decode_cert(tf_path)
    except Exception as e:
        logger.debug(f"Failed to decode DER cert: {e}")
        return None
    finally:
        if tf_path and os.path.exists(tf_path):
            try:
                os.remove(tf_path)
            except OSError:
                pass


def extract_revocation_endpoints(cert_obj):
    """
    Extracts OCSP AIA URLs and CRL Distribution Points from an x509 Certificate object.
    """
    ocsp_urls = []
    crl_urls = []

    try:
        # 1. Authority Information Access (OCSP URLs)
        aia_ext = cert_obj.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for desc in aia_ext.value:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    ocsp_urls.append(desc.access_location.value)
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        logger.debug(f"Failed extracting AIA extension: {e}")

    try:
        # 2. CRL Distribution Points
        crl_ext = cert_obj.extensions.get_extension_for_oid(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        for dp in crl_ext.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        crl_urls.append(name.value)
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        logger.debug(f"Failed extracting CRL distribution points: {e}")

    return ocsp_urls, crl_urls


def check_ocsp_revocation(leaf_cert, issuer_cert, ocsp_url, timeout=5):
    """
    Builds and dispatches an OCSP request over HTTP and evaluates the responder status.
    """
    try:
        # Build OCSP request
        builder = OCSPRequestBuilder()
        builder = builder.add_certificate(leaf_cert, issuer_cert, hashes.SHA256())
        ocsp_req = builder.build()
        req_data = ocsp_req.public_bytes(Encoding.DER)

        # Enforce HTTP/HTTPS scheme
        parsed_url = urllib.parse.urlparse(ocsp_url)
        if parsed_url.scheme not in ("http", "https"):
            return "UNKNOWN", f"Unsupported scheme: {parsed_url.scheme}"

        req = urllib.request.Request(
            ocsp_url,
            data=req_data,
            headers={"Content-Type": "application/ocsp-request"},
        )

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ocsp_resp_data = resp.read()

        ocsp_response = load_der_ocsp_response(ocsp_resp_data)
        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
            return (
                "UNKNOWN",
                f"OCSP responder error: {ocsp_response.response_status.name}",
            )

        # Evaluate certificate status
        if ocsp_response.certificate_status == OCSPCertStatus.GOOD:
            return "GOOD", None
        elif ocsp_response.certificate_status == OCSPCertStatus.REVOKED:
            revocation_time = ocsp_response.revocation_time_utc.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            reason = (
                ocsp_response.revocation_reason.name
                if ocsp_response.revocation_reason
                else "Unspecified"
            )
            return "REVOKED", f"Revoked at {revocation_time}, reason: {reason}"
        else:
            return "UNKNOWN", "Certificate status unknown to responder"

    except Exception as e:
        logger.debug(f"OCSP check failed for {ocsp_url}: {e}")
        return "ERROR", str(e)


def extract_cert_data(host, port, sni, timeout, verify_cert):
    """Connects via TLS handshake, extracts certificate details, and returns a dict."""
    now_utc = datetime.now(timezone.utc)

    # Security: Validate target host against SSRF blocklist
    prohibited, reason = is_prohibited_ip(host)
    if prohibited:
        logger.warning(f"Blocked connection attempt to prohibited target: {host}")
        return {
            "target_host": host,
            "target_port": port,
            "sni": sni,
            "scan_time": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "SECURITY_ERROR",
            "error_message": reason,
        }

    record = {
        "target_host": host,
        "target_port": port,
        "sni": sni,
        "scan_time": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "UNKNOWN",
        "error_message": None,
    }

    try:
        ctx = ssl.create_default_context()
        if not verify_cert:
            # Audit mode for internal PKI and staging hosts
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                # -------------------------------------------------------------
                # Certificate Chain Extraction
                # -------------------------------------------------------------
                chain_certs = []

                # get_verified_chain() returns the full chain (Leaf -> Intermediates -> Root)
                if hasattr(ssock, "get_verified_chain"):
                    verified_chain = ssock.get_verified_chain()
                    if verified_chain:
                        for cert_obj in verified_chain:
                            try:
                                if hasattr(cert_obj, "public_bytes"):
                                    from cryptography.hazmat.primitives import (
                                        serialization,
                                    )

                                    der_data = cert_obj.public_bytes(
                                        serialization.Encoding.DER
                                    )
                                elif hasattr(cert_obj, "to_cryptography"):
                                    from cryptography.hazmat.primitives import (
                                        serialization,
                                    )

                                    der_data = cert_obj.to_cryptography().public_bytes(
                                        serialization.Encoding.DER
                                    )
                                else:
                                    der_data = bytes(cert_obj)
                                decoded = parse_der_bytes(der_data)
                                if decoded:
                                    parsed = format_cert_dict(decoded, now_utc)
                                    if parsed:
                                        chain_certs.append(parsed)
                            except Exception:
                                pass

                # Fallback: Leaf-only if get_verified_chain was empty or unverified
                if not chain_certs:
                    cert = ssock.getpeercert()
                    if not cert and not verify_cert:
                        der_bytes = ssock.getpeercert(binary_form=True)
                        if der_bytes:
                            cert = parse_der_bytes(der_bytes)

                    if cert:
                        leaf_parsed = format_cert_dict(cert, now_utc)
                        if leaf_parsed:
                            chain_certs.append(leaf_parsed)

                # Assign Chain Metadata
                record["tls_version"] = tls_version
                record["cipher"] = cipher_info[0] if cipher_info else None
                record["cipher_bits"] = cipher_info[2] if cipher_info else None
                record["chain_length"] = len(chain_certs)
                record["certificate_chain"] = chain_certs

                if chain_certs:
                    leaf = chain_certs[0]
                    # Keep top-level keys for backward-compatibility with CIM & existing dashboards
                    record.update(
                        {
                            "subject_cn": leaf["subject_cn"],
                            "subject_org": leaf["subject_org"],
                            "subject_alt_names": leaf["subject_alt_names"],
                            "issuer_cn": leaf["issuer_cn"],
                            "issuer_org": leaf["issuer_org"],
                            "serial_number": leaf["serial_number"],
                            "valid_from": leaf["valid_from"],
                            "valid_to": leaf["valid_to"],
                            "days_remaining": leaf["days_remaining"],
                            "is_expired": leaf["is_expired"],
                            "status": "EXPIRED" if leaf["is_expired"] else "VALID",
                            "has_missing_intermediate": len(chain_certs) == 1
                            and not leaf["is_self_signed"],
                        }
                    )

                    # Flag issues across any intermediate or root certificate in the chain
                    chain_expirations = [c["days_remaining"] for c in chain_certs]
                    record["min_chain_days_remaining"] = min(chain_expirations)
                    if record["min_chain_days_remaining"] <= 0:
                        record["status"] = "CHAIN_EXPIRED"
                else:
                    record["status"] = "UNVERIFIED_NO_PARSED_DATA"

                # -------------------------------------------------------------
                # Revocation Check (OCSP / CRL)
                # -------------------------------------------------------------
                revocation_status = "NOT_CHECKED"
                revocation_reason = None
                ocsp_endpoints = []
                crl_endpoints = []

                # Convert leaf and issuer to cryptography.x509 objects if present
                if len(chain_certs) >= 2:
                    try:
                        leaf_der = ssock.getpeercert(binary_form=True)
                        leaf_x509 = x509.load_der_x509_certificate(leaf_der)

                        # Extract issuer x509 from verified chain
                        issuer_der = None
                        if hasattr(ssock, "get_verified_chain"):
                            v_chain = ssock.get_verified_chain()
                            if len(v_chain) >= 2:
                                if hasattr(v_chain[1], "public_bytes"):
                                    issuer_der = v_chain[1].public_bytes(Encoding.DER)
                                elif hasattr(v_chain[1], "to_cryptography"):
                                    issuer_der = (
                                        v_chain[1]
                                        .to_cryptography()
                                        .public_bytes(Encoding.DER)
                                    )

                        if leaf_x509 and issuer_der:
                            issuer_x509 = x509.load_der_x509_certificate(issuer_der)
                            ocsp_endpoints, crl_endpoints = (
                                extract_revocation_endpoints(leaf_x509)
                            )

                            if ocsp_endpoints:
                                # Query the primary OCSP responder
                                status, reason = check_ocsp_revocation(
                                    leaf_x509,
                                    issuer_x509,
                                    ocsp_endpoints[0],
                                    timeout=timeout,
                                )
                                revocation_status = status
                                revocation_reason = reason
                    except Exception as rev_err:
                        logger.debug(
                            f"Failed performing revocation evaluation: {rev_err}"
                        )
                        revocation_status = "EVALUATION_ERROR"
                        revocation_reason = str(rev_err)

                record["revocation_status"] = revocation_status
                record["revocation_reason"] = revocation_reason
                record["ocsp_responders"] = ocsp_endpoints
                record["crl_distribution_points"] = crl_endpoints

                # If certificate has been explicitly revoked, override overall status
                if revocation_status == "REVOKED":
                    record["status"] = "REVOKED"

    except ssl.SSLCertVerificationError as e:
        record["status"] = "VERIFICATION_FAILED"
        record["error_message"] = str(e)
        logger.info(f"Certificate verification failed for {host}:{port} ({sni}): {e}")
    except ssl.SSLError as e:
        record["status"] = "TLS_HANDSHAKE_ERROR"
        record["error_message"] = str(e)
        logger.info(f"TLS handshake error for {host}:{port} ({sni}): {e}")
    except TimeoutError:
        record["status"] = "TIMEOUT"
        record["error_message"] = f"Connection timed out after {timeout}s"
        logger.info(f"Timeout connecting to {host}:{port} ({sni})")
    except (OSError, ValueError, KeyError, TypeError) as e:
        record["status"] = "CONNECTION_ERROR"
        record["error_message"] = str(e)
        logger.info(f"Connection error for {host}:{port} ({sni}): {e}")

    return record


def resolve_csv_path(filename):
    """Resolves CSV filename in local app lookups directory or direct absolute path."""
    if os.path.isabs(filename) and os.path.isfile(filename):
        return filename

    # Resolve relative to TA app root / lookups
    app_root = os.path.dirname(BIND_DIR)
    lookup_path = os.path.join(app_root, "lookups", filename)
    if os.path.isfile(lookup_path):
        return lookup_path

    return None


def load_targets_from_csv(csv_path):
    """Yields sanitized target parameter dictionaries from CSV."""
    targets = []
    try:
        with open(csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                host = row.get("target_host", "").strip()
                if not host:
                    continue
                try:
                    port = int(row.get("port", 443))
                except ValueError:
                    port = 443

                sni = row.get("sni", "").strip() or host

                try:
                    timeout = min(float(row.get("timeout", 10)), 30.0)
                except ValueError:
                    timeout = 10.0

                verify_cert = str(row.get("verify_cert", "true")).lower() in (
                    "true",
                    "1",
                    "yes",
                )

                targets.append(
                    {
                        "target_host": host,
                        "port": port,
                        "sni": sni,
                        "timeout": timeout,
                        "verify_cert": verify_cert,
                    }
                )
    except Exception as e:
        logger.error(f"Error reading CSV {csv_path}: {e}")
    return targets


def run_input():
    """Reads XML configuration from Splunk on stdin and streams XML events on stdout."""
    config_str = sys.stdin.read()
    if not config_str:
        return

    root = ET.fromstring(config_str)

    sys.stdout.write("<stream>\n")

    for input_node in root.findall(".//configuration/stanza"):
        stanza_name = input_node.get("name", "")

        params = {}
        for param in input_node.findall("param"):
            params[param.get("name")] = param.text

        # =========================================================================
        # 1. READ GENERAL / DEFAULT PARAMETERS
        # =========================================================================
        csv_file = params.get("targets_csv")
        target_host = params.get("target_host")

        try:
            port = int(params.get("port", 443))
        except ValueError:
            port = 443

        sni = params.get("sni") or target_host

        try:
            timeout = min(float(params.get("timeout", 10)), 30.0)
        except ValueError:
            timeout = 10.0

        verify_cert = str(params.get("verify_cert", "true")).lower() in (
            "true",
            "1",
            "yes",
        )

        # =========================================================================
        # 2. BUILD THE LIST OF TARGETS (CSV BULK MODE vs SINGLE TARGET MODE)
        # =========================================================================
        targets = []

        if csv_file and csv_file.strip():
            resolved_csv = resolve_csv_path(csv_file.strip())
            if resolved_csv:
                targets = load_targets_from_csv(resolved_csv)
            else:
                log_err(
                    f"Could not locate targets_csv at: {csv_file} for stanza: {stanza_name}"
                )
                continue
        elif target_host and target_host.strip():
            targets = [
                {
                    "target_host": target_host.strip(),
                    "port": port,
                    "sni": sni,
                    "timeout": timeout,
                    "verify_cert": verify_cert,
                }
            ]
        else:
            log_err(
                f"Stanza '{stanza_name}' must specify either 'targets_csv' or 'target_host'"
            )
            continue

        # =========================================================================
        # 3. EXECUTE CHECKS & STREAM XML EVENTS
        # =========================================================================
        for t in targets:
            cert_data = extract_cert_data(
                t["target_host"], t["port"], t["sni"], t["timeout"], t["verify_cert"]
            )

            sys.stdout.write("<event>\n")
            sys.stdout.write(f"<stanza>{stanza_name}</stanza>\n")
            sys.stdout.write("<sourcetype>cert:ssl:json</sourcetype>\n")
            sys.stdout.write(f"<data><![CDATA[{json.dumps(cert_data)}]]></data>\n")
            sys.stdout.write("</event>\n")
            sys.stdout.flush()

    sys.stdout.write("</stream>\n")
    sys.stdout.flush()


def validate_arguments():
    """Validates configuration parameters passed during stanza creation in the UI/CLI."""
    input_str = sys.stdin.read()
    root = ET.fromstring(input_str)
    params = {}
    for param in root.findall(".//configuration/stanza/param"):
        params[param.get("name")] = param.text

    csv_file = params.get("targets_csv")
    host = params.get("target_host")

    # =========================================================================
    # 1. ENSURE AT LEAST ONE TARGET MECHANISM IS DEFINED
    # =========================================================================
    if not (csv_file and csv_file.strip()) and not (host and host.strip()):
        sys.stderr.write(
            "Validation error: Either 'targets_csv' or 'target_host' must be specified.\n"
        )
        sys.exit(1)

    # =========================================================================
    # 2. VALIDATE CSV PATH (IF PROVIDED)
    # =========================================================================
    if csv_file and csv_file.strip():
        resolved_path = resolve_csv_path(csv_file.strip())
        if not resolved_path:
            sys.stderr.write(
                f"Validation error: Target CSV '{csv_file}' was not found in 'lookups/' or as an absolute path.\n"
            )
            sys.exit(1)

    # =========================================================================
    # 3. VALIDATE SINGLE TARGET HOST (IF PROVIDED)
    # =========================================================================
    if host and host.strip():
        prohibited, reason = is_prohibited_ip(host.strip())
        if prohibited:
            sys.stderr.write(f"Validation error: {reason}\n")
            sys.exit(1)

    # =========================================================================
    # 4. VALIDATE PORT & TIMEOUT RANGES
    # =========================================================================
    port = params.get("port")
    if port:
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError()
        except ValueError:
            sys.stderr.write(
                "Validation error: port must be an integer between 1 and 65535.\n"
            )
            sys.exit(1)

    timeout = params.get("timeout")
    if timeout:
        try:
            timeout_val = float(timeout)
            if timeout_val <= 0 or timeout_val > 30:
                raise ValueError()
        except ValueError:
            sys.stderr.write(
                "Validation error: timeout must be between 1 and 30 seconds.\n"
            )
            sys.exit(1)

    sys.exit(0)


def print_scheme():
    """Reads introspection XML schema from an external file and prints to stdout."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scheme_path = os.path.join(script_dir, "scheme.xml")

    try:
        with open(scheme_path, "r", encoding="utf-8") as f:
            sys.stdout.write(f.read())
            sys.stdout.flush()
    except FileNotFoundError:
        log_err(f"Schema file not found at: {scheme_path}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        if mode == "--scheme":
            print_scheme()
        elif mode == "--validate-arguments":
            validate_arguments()
        else:
            log_err(f"Unknown argument: {mode}")
            sys.exit(1)
    else:
        run_input()
