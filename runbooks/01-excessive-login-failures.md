# Runbook: Excessive Login Failures - T1110 Brute Force

## What this detects
5+ failed logon attempts against a single account within a 2 minute window (Windows Event ID 4625, grouped by `user.name`, threshold set above 3).

## MITRE ATT&CK
Tactic: Credential Access (TA0006)
Technique: Brute Force (T1110)

## Triage steps
1. Check which account is affected and how many attempts were made.
2. Check the source (workstation name, IP if available) the attempts came from.
3. Confirm this isn't the account owner locked out of their own login.
4. If the pattern looks malicious (external source, unusual time, unfamiliar account), escalate to containment.

## Response taken (lab evidence)
Account was disabled using `Disable-LocalUser -Name "testuser"` following 5 failed logon attempts within 2 minutes. Verified via `Get-LocalUser -Name "testuser"` showing `Enabled: False`. This mirrors the real world action of locking a targeted account while the source of the attempts is investigated.
