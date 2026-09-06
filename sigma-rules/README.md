# Sigma Rules

Vendor-agnostic Sigma versions of all five Elastic detection rules in this lab. Writing detections in Sigma first means the same logic can be converted to Elastic, Splunk, Sentinel or QRadar query syntax using `sigma-cli`, rather than being locked to one platform.

- [Excessive Login Failures (T1110)](01-excessive-login-failures.yml)
- [Disabled Account Sign-In Attempt (T1078)](02-disabled-account-signin.yml)
- [Login Outside the UK, Anomalous Geolocation (T1078)](03-anomalous-geolocation.yml)
- [Mass Download Detected (T1074)](04-mass-download.yml)
- [Anonymous Link Used for Download (T1567.002)](05-anonymous-link-download.yml)

Note on rule 3: GeoIP fields are enrichment output, not a native Windows event field, so this rule assumes a GeoIP ingest pipeline has already run against `source.ip`. Note on rule 5: sourced from Microsoft 365's unified audit log schema, not Windows Security events, so it uses `product: m365` rather than `product: windows`.
