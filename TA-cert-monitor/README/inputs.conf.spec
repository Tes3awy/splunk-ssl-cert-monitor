[cert_checker://<name>]
* Monitors and extracts SSL/TLS certificate metadata and expiration.

target_host = <value>
* The hostname or IP address of the remote target.

port = <value>
* Target port (defaults to 443 if omitted).

sni = <value>
* Server Name Indication (SNI) string. If omitted, target_host is used.

timeout = <value>
* Socket connection timeout in seconds (default: 10).

verify_cert = <value>
* Whether to verify CA signature (true/false, default: true). Set false for self-signed or internal CA endpoints.