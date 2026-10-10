[cert_alert_webhook]
* Modular alert action for posting certificate expiration notices to webhooks.

python.version = <string>
* Python interpreter to run the alert script.

python.required = <string>
* Python target version for Splunk Cloud compatibility.

param.auth_token = <string>
* Authentication token.

param.webhook_url = <string>
* HTTPS destination URL where payload JSON will be posted.

param.severity = <string>
* Severity level override for the outgoing alert (critical, warning, info).
