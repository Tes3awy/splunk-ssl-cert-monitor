[cert_checker://<name>]
* Modular input for monitoring SSL/TLS certificates and OCSP statuses.

target_host = <value>
* Hostname or IP address of the target TLS endpoint.

port = <value>
* Port number of the target TLS endpoint (default: 443).

sni = <value>
* Server Name Indication hostname.

timeout = <value>
* Connection timeout in seconds.

verify_cert = <value>
* Whether to enforce strict CA trust verification (0 | 1 | true | false).

audit_legacy_protocols = <value>
* Whether to probe for deprecated TLS 1.0 and TLS 1.1 support (0 | 1 | true | false).