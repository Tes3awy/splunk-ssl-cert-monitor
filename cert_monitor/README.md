[![Splunkbase](https://img.shields.io/badge/Splunkbase-TA--cert--monitor-blue.svg)](https://splunkbase.splunk.com/app/9906)
[![Splunkbase](https://img.shields.io/badge/Splunkbase-splunk--app--cert--monitor-brightgreen.svg)](https://splunkbase.splunk.com/app/9907)
[![Splunk AppInspect CI](https://github.com/Tes3awy/splunk-ssl-cert-monitor/actions/workflows/appinspect.yml/badge.svg)](https://github.com/Tes3awy/splunk-ssl-cert-monitor/actions/workflows/appinspect.yml)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)


# Dashboards Overview

## Executive Overview (`cert_overview`):

- KPI cards displaying Total Endpoints, Active Valid Certificates, Expiring ($\le 30$ days), and Critical Expired/Revoked
- Expiration timeline distribution (Bucketed Pie Chart).
- TLS Protocol Version and Negotiated Cipher Suite distribution.
- Searchable certificate inventory table with color-coded health badges and host filtering.

## Security Audit (`cert_audit`):

- Insecure protocol (`TLSv1.0`, `TLSv1.1`, `SSLv3`) and weak cipher (`RC4`, `3DES`, `NULL`) audit.
- Self-signed & internal non-CA certificate detection.
- Real-time OCSP revocation and endpoint connection failure logs.

# Support & Contributing

- Author: Osama Abbas
- License: Apache License 2.0
- Issue Tracker & Source: [GitHub Repository](https://github.com/Tes3awy/splunk-ssl-cert-monitor)
