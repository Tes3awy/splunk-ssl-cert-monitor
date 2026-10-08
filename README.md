[![Splunkbase](https://img.shields.io/badge/Splunkbase-TA--cert--monitor-blue.svg)](https://splunkbase.splunk.com/app/9906)
[![Splunkbase](https://img.shields.io/badge/Splunkbase-splunk--app--cert--monitor-brightgreen.svg)](https://splunkbase.splunk.com/app/9907)
[![Splunk AppInspect CI](https://github.com/Tes3awy/splunk-ssl-cert-monitor/actions/workflows/appinspect.yml/badge.svg)](https://github.com/Tes3awy/splunk-ssl-cert-monitor/actions/workflows/appinspect.yml)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)


# SSL / TLS Certificate Monitor App & Technology Add-on

Proactively monitor SSL/TLS certificate validity, countdown expiration dates, audit weak ciphers and legacy TLS protocols, track live OCSP revocation, and eliminate unplanned web and API outages across your infrastructure.

This solution is split into two modular packages following Splunk architectural best practices:

1. **`TA-cert-monitor`** (Technology Add-on): Contains the Python 3 modular input (`cert_checker`), modular alert action (`cert_alert_webhook`), data collection engine, index-time parsing, and Splunk Common Information Model (CIM) field normalization.
2. **`splunk-app-cert-monitor`** (Visualization App): Delivers operational dashboards, single-value KPI countdown cards, scheduled alerts, and security audit tables.

---

## Key Features

- **Proactive Expiration Tracking:** Automatically calculates `days_remaining` and categorizes certificate urgency (`Critical <= 15d`, `Warning 16-30d`, `Expired`, `Healthy > 60d`).
- **Live OCSP Revocation Checking:** Inquires Authority Information Access (AIA) OCSP responders to detect revoked certificates before expiration.
- **Server Name Indication (SNI) Support:** Inspect multi-tenant hosts, reverse proxies, CDNs (Cloudflare, Akamai, CloudFront), and Kubernetes ingress controllers where the virtual host SNI differs from the underlying target IP.
- **Cipher & Protocol Audits:** Tracks negotiated TLS versions (`TLSv1.2`, `TLSv1.3`) and flags legacy/insecure protocols (`TLSv1.0`, `TLSv1.1`, `SSLv3`) and weak ciphers (RC4, 3DES, NULL).
- **Custom Modular Alert Action (`cert_alert_webhook`):** Send structured alerts with TLS 1.2+ validation directly to external incident management endpoints (Slack, Microsoft Teams, Opsgenie, PagerDuty, Webhooks).
- **Self-Signed & Internal CA Support:** Configurable root verification toggle allows auditing internal development clusters, private enterprise PKI, or expired certificates without aborting data collection.
- **Splunk CIM Compliant:** Out-of-the-box normalization to the Splunk CIM **Certificates** data model (`tag=certificate`).
- **Splunk Cloud & Python 3.13 Ready:** Built with the Splunk UCC Framework and audited with Splunk AppInspect (0 errors, 0 failures).

---

## Topology & Deployment Architecture

| Splunk Tier                             | `TA-cert-monitor`                              | `splunk-app-cert-monitor`                  |
| :-------------------------------------- | :--------------------------------------------- | :----------------------------------------- |
| **Search Heads / Search Head Clusters** | Required (Field aliases, CIM, Alert Action UI) | Required (Dashboards, Nav, Saved Searches) |
| **Indexers / Indexer Clusters**         | Required (`props.conf` only)                   | Not Needed                                 |
| **Heavy Forwarders / IDM**              | Required (Runs Modular Input)                  | Not Needed                                 |
| **Universal Forwarders**                | Not Supported (Requires Python 3 runtime)      | Not Needed                                 |

---

## Installation

### Option 1: Splunk Web UI (Recommended)

1. Log in to your Splunk Search Head or Heavy Forwarder as an administrator.
2. Navigate to **Apps > Manage Apps > Install App from File**.
3. Upload `TA-cert-monitor-2.1.2.tar.gz` and click **Upload**.
4. Repeat the process to upload `splunk-app-cert-monitor-2.1.2.tar.gz`.
5. Restart Splunk if prompted.

### Option 2: Command Line (CLI)

Extract both packages into `$SPLUNK_HOME/etc/apps/`:

```bash
tar -xzvf TA-cert-monitor-2.1.2.tar.gz -C $SPLUNK_HOME/etc/apps/
tar -xzvf splunk-app-cert-monitor-2.1.2.tar.gz -C $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

## Configuration

### 1. Configure the Target Index Macro

By default, the dashboard and alerts search using the `ssl_cert_index` macro (defaults to `index=ssl_cert` OR `index=main`). If you store certificate metrics in a dedicated index:

1. Go to **Settings > Advanced Search > Search Macros**.
2. Locate `ssl_cert_index` under **App: splunk-app-cert-monitor**.
3. Update the definition to your target index: `index=your_index_name`.

### 2. Add Certificate Monitoring Inputs

#### Via Splunk Web UI (TA-cert-monitor):

1. Navigate to **Apps > TA-cert-monitor > Inputs**.
2. Click **Create New Input**:
   - Name: Unique stanza name (e.g., `prod_api_gateway`).
   - Target Host / IP: Hostname or IP address (e.g., `api.example.com` or `10.0.0.25`).
   - Port: SSL/TLS port (Default: `443`).
   - SNI: Server Name Indication string (defaults to Target Host if left blank).
   - Interval: Polling frequency in seconds (e.g., `86400` for once every 24 hours).
   - Strict Root Verification: Check `true` for standard CA trust validation. Leave unchecked (`false`) to audit internal PKI or self-signed certs.
   - Audit Legacy Protocols: Actively probe the endpoint for deprecated TLS 1.0 and TLS 1.1 support.
   - Index: Choose your destination index.

## Via `inputs.conf` Directly

```ini
[cert_checker://prod_public_portal]
target_host = portal.example.com
port = 443
sni = portal.example.com
interval = 43200
verify_cert = true
audit_legacy_protocols = true
timeout = 10
index = ssl_cert

[cert_checker://internal_microservice]
target_host = 192.0.2.50
port = 8443
sni = service.corp.local
interval = 86400
verify_cert = false
audit_legacy_protocols = false
timeout = 5
index = ssl_cert
```

## Splunk Common Information Model (CIM) Mapping

`TA-cert-monitor` normalizes events into the **Certificates** data model. Events are automatically tagged with `certificate`.

| JSON Field            | CIM Certificates Field                   | Description / Transformation                      |
| --------------------- | ---------------------------------------- | ------------------------------------------------- |
| `dest`                | `dest`                                   | Target endpoint IP or hostname                    |
| `dest_port`           | `dest_port`                              | Target TLS connection port                        |
| `subject_cn`          | `ssl_subject`, `ssl_subject_common_name` | Certificate Common Name                           |
| `subject_org`         | `ssl_subject_unit`                       | Subject organization                              |
| `san_list{}`          | `ssl_subject_alt_name`                   | Multivalue Subject Alternative Names (SANs)       |
| `issuer_org`          | `ssl_issuer`                             | Issuing Certificate Authority                     |
| `issuer_cn`           | `ssl_issuer_common_name`                 | Issuer Common Name                                |
| `serial_number`       | `ssl_serial`                             | Certificate serial number                         |
| `cipher`              | `ssl_cipher`                             | Negotiated TLS cipher suite                       |
| `valid_from`          | `ssl_start_time`                         | Validity start epoch                              |
| `valid_to`            | `ssl_end_time`                           | Expiration date epoch                             |
| `status`              | `ssl_is_valid`                           | `true` if valid, `false` if expired/revoked       |
| `ssl_version`         | `ssl_version`                            | TLS protocol version (e.g., `TLSv1.3`, `TLSv1.2`) |
| `has_legacy_tls`      | *Custom*                                 | True if endpoint accepts TLS 1.0/1.1              |

### Example CIM Search

```spl
| datamodel Certificates search
| search Certificates.ssl_end_time=*
| eval days_left = round((Certificates.ssl_end_time - now()) / 86400, 1)
| table Certificates.dest, Certificates.ssl_subject, Certificates.ssl_issuer, days_left, Certificates.ssl_version
| sort days_left
```

## Dashboards Overview

### Executive Overview (`cert_overview`):

- KPI cards displaying Total Endpoints, Active Valid Certificates, Expiring ($\le 30$ days), and Critical Expired/Revoked
- Expiration timeline distribution (Bucketed Pie Chart).
- TLS Protocol Version and Negotiated Cipher Suite distribution.
- Searchable certificate inventory table with color-coded health badges and host filtering.

### Security Audit (`cert_audit`):

- Insecure protocol (`TLSv1.0`, `TLSv1.1`, `SSLv3`) and weak cipher (`RC4`, `3DES`, `NULL`) audit.
- Self-signed & internal non-CA certificate detection.
- Real-time OCSP revocation and endpoint connection failure logs.

## Support & Contributing

- Author: Osama Abbas
- License: Apache License 2.0
- Issue Tracker & Source: [GitHub Repository](https://github.com/Tes3awy/splunk-ssl-cert-monitor)
