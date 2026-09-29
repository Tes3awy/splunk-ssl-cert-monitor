#!/usr/bin/env python3
"""
Splunk Modular Input: SSL/TLS Certificate Monitor
Collects certificate expiration, issuer, subject, SANs, and cipher details via SNI.
"""

import ipaddress
import json
import os
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def log_err(message):
    """Logs errors to splunkd.log with standard log channel format."""
    sys.stderr.write(f"ERROR cert_checker: {message}\n")
    sys.stderr.flush()


def is_prohibited_ip(host_str):
    """
    Blocks direct connection attempts to cloud metadata IP addresses
    and IPv4/IPv6 loopback targets to prevent SSRF abuse.
    """
    try:
        ip = ipaddress.ip_address(host_str)
        # ip.is_link_local covers 169.254.0.0/16 (AWS/Azure/GCP metadata) and fe80::/10
        if ip.is_link_local or ip.is_loopback:
            return (
                True,
                "Access to link-local, loopback, and cloud metadata addresses is prohibited.",
            )
    except ValueError:
        # It is a hostname, not an IP string
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


def extract_cert_data(host, port, sni, timeout, verify_cert):
    """Connects via TLS handshake, extracts certificate details, and returns a dict."""
    now_utc = datetime.now(timezone.utc)

    # Security: Validate target host against SSRF blacklist
    prohibited, reason = is_prohibited_ip(host)
    if prohibited:
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
        # Create SSL context based on verification flag
        ctx = ssl.create_default_context()
        if not verify_cert:
            # AppInspect manual-check justification:
            # Inspection tool designed to audit expired or untrusted internal PKI certs
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                # When verify_mode == CERT_NONE, getpeercert() is empty.
                # In Python 3 standard library, ssl._ssl._test_decode_cert decodes
                # raw DER certificates into the exact same dict getpeercert() returns.
                if not cert and not verify_cert:
                    der_bytes = ssock.getpeercert(binary_form=True)
                    if der_bytes:
                        try:
                            # Decode raw DER using Python's internal OpenSSL parser
                            import tempfile

                            with tempfile.NamedTemporaryFile(delete=True) as tf:
                                tf.write(der_bytes)
                                tf.flush()
                                cert = ssl._ssl._test_decode_cert(tf.name)
                        except Exception:
                            # Fallback if internal decoder is unavailable
                            cert = {}

                record["tls_version"] = tls_version
                record["cipher"] = cipher_info[0] if cipher_info else None
                record["cipher_bits"] = cipher_info[2] if cipher_info else None

                if cert:
                    subject_dict = parse_dn(cert.get("subject", ()))
                    issuer_dict = parse_dn(cert.get("issuer", ()))
                    sans = [
                        item[1]
                        for item in cert.get("subjectAltName", [])
                        if item[0] == "DNS"
                    ]

                    not_before = parse_ssl_date(cert["notBefore"])
                    not_after = parse_ssl_date(cert["notAfter"])
                    days_remaining = (not_after - now_utc).total_seconds() / 86400.0

                    record.update(
                        {
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
                            "status": "EXPIRED" if days_remaining <= 0 else "VALID",
                        }
                    )
                else:
                    record["status"] = "UNVERIFIED_NO_PARSED_DATA"

    except ssl.SSLCertVerificationError as e:
        record["status"] = "VERIFICATION_FAILED"
        record["error_message"] = str(e)
    except ssl.SSLError as e:
        record["status"] = "TLS_HANDSHAKE_ERROR"
        record["error_message"] = str(e)
    except TimeoutError:
        record["status"] = "TIMEOUT"
        record["error_message"] = f"Connection timed out after {timeout}s"
    except (OSError, ValueError, KeyError, TypeError) as e:
        record["status"] = "CONNECTION_ERROR"
        record["error_message"] = str(e)

    return record


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

        target_host = params.get("target_host")
        if not target_host:
            log_err(f"Missing target_host for stanza: {stanza_name}")
            continue

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

        cert_data = extract_cert_data(target_host, port, sni, timeout, verify_cert)

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

    host = params.get("target_host")
    if not host or not host.strip():
        sys.stderr.write("Validation error: target_host cannot be empty.\n")
        sys.exit(1)

    prohibited, reason = is_prohibited_ip(host.strip())
    if prohibited:
        sys.stderr.write(f"Validation error: {reason}\n")
        sys.exit(1)

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
    # Resolve the absolute path relative to this script file
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
