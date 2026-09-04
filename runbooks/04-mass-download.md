# Runbook: Mass Download Detected - Bulk File Access (T1074 Data Staged)

## What this detects
A single user account reading more than 10 files within a short window (Windows Event ID 4663, object access auditing). May indicate bulk data staging ahead of exfiltration, or an offboarding employee copying data before leaving.

## MITRE ATT&CK
Tactic: Collection (TA0009)
Technique: Data Staged (T1074)

## Triage steps
1. Identify which files were accessed and whether they contain sensitive data.
2. Check whether the access pattern matches the user's normal role.
3. Check the time of access for anything unusual (late night, weekend, right before a resignation date).

## Response taken (lab evidence)
Demonstrated restricting further access to the affected data using `icacls <path> /deny "Everyone:(OI)(CI)RX"`, confirmed the Deny entry was applied via a follow-up `icacls` check. In a production environment this would be scoped to the specific offending account's access on the affected file share, rather than "Everyone", pending investigation.
