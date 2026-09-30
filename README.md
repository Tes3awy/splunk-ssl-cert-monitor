[![Splunkbase](https://img.shields.io/badge/Splunkbase-TA--cert--monitor-blue.svg)](https://splunkbase.splunk.com/app/9906)
[![Splunkbase](https://img.shields.io/badge/Splunkbase-splunk--app--cert--monitor-brightgreen.svg)](https://splunkbase.splunk.com/app/9907)

# SSL / TLS Certificate Monitor App & Technology Add-on

Proactively monitor SSL/TLS certificate validity, countdown expiration dates, audit weak ciphers and legacy TLS protocols, and eliminate unplanned web and API outages across your infrastructure.

This solution is split into two modular packages following Splunk architectural best practices:

1. **`TA-cert-monitor`** (Technology Add-on): Contains the Python 3 modular input, data collection engine, index-time parsing, and Splunk Common Information Model (CIM) field normalization.
2. **`splunk-app-cert-monitor`** (Visualization App): Delivers operational dashboards, single-value KPI countdown cards, and security audit tables.

---

## Key Features

* **Proactive Expiration Tracking:** Automatically calculates `days_remaining` and categorizes certificate urgency (`Critical <= 15d`, `Warning 16-30d`, `Expired`, `Healthy > 60d`).
* **Server Name Indication (SNI) Support:** Inspect multi-tenant hosts, reverse proxies, CDNs (Cloudflare, Akamai), and Kubernetes ingress controllers where the virtual host SNI differs from the underlying target IP.
* **Cipher & Protocol Audits:** Tracks negotiated TLS versions (`TLSv1.2`, `TLSv1.3`) and flags legacy/insecure protocols (`TLSv1.0`, `TLSv1.1`, `SSLv3`) and weak ciphers (RC4, 3DES).
* **Self-Signed & Internal CA Support:** Configurable certificate verification toggle allows scanning internal development clusters, private enterprise PKI, or already-expired certificates without handshake abortions.
* **Splunk CIM Compliant:** Full out-of-the-box normalization to the Splunk CIM **Certificates** data model (`tag=certificate`).
* **Lightweight & Dependency-Free:** Built strictly with Python 3 standard libraries (`socket`, `ssl`). Zero external pip dependencies required.

---

## Topology & Deployment Architecture

| Splunk Tier                             | `TA-cert-monitor`                         | `splunk-app-cert-monitor`     |
| --------------------------------------- | ----------------------------------------- | ----------------------------- |
| **Search Heads / Search Head Clusters** | Required (Field aliases & CIM)            | Required (Dashboards & Views) |
| **Indexers / Indexer Clusters**         | Required (`props.conf` only)              | Not Needed                    |
| **Heavy Forwarders / IDM**              | Required (Runs Modular Input)             | Not Needed                    |
| **Universal Forwarders**                | Not Supported (Requires Python 3 runtime) | Not Needed                    |

---

## Installation

### Option 1: Splunk Web UI (Simplest)

1. Log in to your Splunk Search Head or Heavy Forwarder as an administrator.
2. Navigate to **Apps > Manage Apps > Install App from File**.
3. Upload `TA-cert-monitor-1.0.0.tar.gz` and click **Upload**.
4. Repeat the process to upload `splunk-app-cert-monitor-1.0.0.tar.gz`.
5. Restart Splunk if prompted.

### Option 2: Command Line (Advanced via CLI)

Extract both packages into `$SPLUNK_HOME/etc/apps/`:

```bash
$ tar -xzvf TA-cert-monitor-1.0.0.tar.gz -C $SPLUNK_HOME/etc/apps/
$ tar -xzvf splunk-app-cert-monitor-1.0.0.tar.gz -C $SPLUNK_HOME/etc/apps/
$ $SPLUNK_HOME/bin/splunk restart
```

---

## Configuration

### 1. Configure the Target Index Macro

By default, the dashboard searches using the `ssl_cert_index` macro (defaults to `index=main`). If you store certificate metrics in a dedicated index (e.g., `index=certificates` or `index=security`), update the macro:

* Go to **Settings > Advanced Search > Search Macros**.
* Locate `ssl_cert_index` under **App: splunk-app-cert-monitor**.
* Change the definition to your target index: `index=your_index_name`.

---

### 2. Add Certificate Monitoring Inputs

#### Via Splunk Web UI:

1. Navigate to **Settings > Data Inputs > SSL/TLS Certificate Monitor**.
2. Click **New**.
3. Complete the input configuration:
* **Input Name:** A unique label (e.g., `prod_api_gateway`).
* **Target Host:** Hostname or IP address (e.g., `api.example.com` or `10.0.0.25`).
* **Port:** SSL/TLS port (Default: `443`).
* **SNI:** Server Name Indication string (defaults to Target Host if left blank).
* **Interval:** Polling frequency in seconds (e.g., `86400` for once every 24 hours, `43200` for twice daily).
* **Verify Certificate:** Check `true` for standard public validation. Uncheck `false` to audit self-signed or internal CA certs.
* **Index:** Choose your destination index.

#### Via `inputs.conf` Directly:

You can deploy inputs across Heavy Forwarders via deployment server using `$SPLUNK_HOME/etc/apps/TA-cert-monitor/local/inputs.conf`:

```ini
[cert_checker://prod_public_portal]
target_host = portal.example.com
port = 443
sni = portal.example.com
interval = 43200
verify_cert = true
timeout = 10
index = main
python.version = python3
python.required = 3.13

[cert_checker://internal_microservice]
target_host = 192.0.2.50
port = 8443
sni = service.corp.local
interval = 86400
verify_cert = false
timeout = 5
index = main
python.version = python3
python.required = 3.13

```

---

## Splunk Common Information Model (CIM) Mapping

`TA-cert-monitor` normalizes events into the **Certificates** data model. Events are automatically tagged with `certificate`.

| JSON Indexed Field    | CIM Certificates Field                   | Description / Transformation                         |
| --------------------- | ---------------------------------------- | ---------------------------------------------------- |
| `target_host`         | `dest`                                   | Target endpoint IP or hostname                       |
| `target_port`         | `dest_port`                              | Target TLS connection port                           |
| `subject_cn`          | `ssl_subject`, `ssl_subject_common_name` | Certificate Common Name                              |
| `subject_org`         | `ssl_subject_unit`                       | Subject organization                                 |
| `subject_alt_names{}` | `ssl_subject_alt_name`                   | Multivalue Subject Alternative Names (SANs)          |
| `issuer_org`          | `ssl_issuer`                             | Issuing Certificate Authority                        |
| `issuer_cn`           | `ssl_issuer_common_name`                 | Issuer Common Name                                   |
| `serial_number`       | `ssl_serial`                             | Certificate serial number                            |
| `cipher`              | `ssl_cipher`                             | Negotiated TLS cipher suite                          |
| `valid_from`          | `ssl_start_time`                         | Validity start epoch (converted via `strptime`)      |
| `valid_to`            | `ssl_end_time`                           | Expiration date epoch (converted via `strptime`)     |
| `status`              | `ssl_is_valid`                           | Boolean string (`true` if valid, `false` if expired) |
| `tls_version`         | `ssl_version`                            | TLS protocol version (e.g., `TLSv1.3`, `TLSv1.2`)    |

### Example CIM Search

```spl
| datamodel Certificates search 
| search Certificates.ssl_end_time=*
| eval days_left = round((Certificates.ssl_end_time - now()) / 86400, 1)
| table Certificates.dest, Certificates.ssl_subject, Certificates.ssl_issuer, days_left, Certificates.ssl_version
| sort days_left

```

---

## Dashboards Overview

* **Certificates Overview (`cert_overview.xml`):**
* Top KPI cards displaying Total Endpoints, Expired Certificates, Critical Expiring ($\le 15$ days), Warning Expiring ($16-30$ days), and Insecure TLS versions detected.
* Visual expiration countdown buckets and Certificate Authority distribution.
* Interactive inventory table with color-coded urgency and host filtering.


* **Security Audit (`cert_audit.xml`):**
* Target list isolating deprecated protocols (`TLSv1.0`, `TLSv1.1`, `SSLv3`) and insecure cipher suites (`RC4`, `3DES`, `NULL`).

---

## Support & Contributing

* **Author:** Osama Abbas
* **License:** Apache License 2.0
* **Issue Tracker & Source:** [GitHub Repository](https://www.google.com/search?q=https://github.com/Tes3awy/splunk-ssl-cert-monitor)
