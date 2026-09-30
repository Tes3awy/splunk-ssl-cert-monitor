[cert_checker://<name>]
* Modular input for monitoring SSL/TLS certificates and endpoints.

python.version = <string>
* Python interpreter version to run the input script (e.g. python3).

python.required = <string>
* Target Python version for Splunk Cloud compatibility (e.g. 3.13).

interval = <string>
* How often to execute the check, in seconds or as a cron schedule string.

targets_csv = <string>
* Optional: Name of a CSV file in lookups/ or an absolute path to a CSV file containing targets.

target_host = <string>
* Target hostname or IP address to connect to (required if targets_csv is not used).

port = <integer>
* Port number to connect to (default: 443).

sni = <string>
* Server Name Indication (SNI) hostname. Defaults to target_host if not specified.

timeout = <number>
* Socket timeout in seconds (default: 10).

verify_cert = <boolean>
* Whether to verify the SSL certificate chain (true/false).