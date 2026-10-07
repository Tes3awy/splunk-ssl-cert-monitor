[ssl_targets]
filename = <string>
* Name of static lookup file.
* File should be in $SPLUNK_HOME/etc/apps/<app_name>/lookups/
* Default: empty string

case_sensitive_match = <boolean>
* If set to true, Splunk software performs case sensitive matching for all
  fields in a lookup table.
* If set to false, Splunk software performs case insensitive matching for all
  fields in a lookup table.
* Default: true
