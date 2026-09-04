# Runbook: Login Outside the UK - Anomalous Geolocation

## What this detects
A successful logon (Windows Event ID 4624) where the source IP resolves, via GeoIP enrichment, to a country outside the UK. May indicate impossible travel or a compromised account.

## MITRE ATT&CK
Tactic: Initial Access / Defense Evasion (context dependent)
Technique: Valid Accounts (T1078), commonly associated with impossible travel detections

## Triage steps
1. Confirm whether the user is legitimately traveling, check with them directly if possible.
2. Check for other suspicious activity from the same session (mailbox rule changes, unusual file access, repeated MFA prompts).
3. If not legitimate, treat the account as compromised and escalate.

## Response taken (lab evidence)
Blocked the source IP at the network level using `New-NetFirewallRule -DisplayName "Block Suspicious GeoIP 8.8.8.8" -Direction Outbound -RemoteAddress 8.8.8.8 -Action Block`, confirmed via `Get-NetFirewallRule`. In production this containment step would typically be paired with forcing a password reset and revoking active sessions/tokens for the account.
