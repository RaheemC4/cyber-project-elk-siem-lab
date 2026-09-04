# Runbook: Disabled Account Sign-In Attempt - T1078 Valid Accounts

## What this detects
A single logon attempt against an account that is currently disabled (Windows Event ID 4625, Sub Status 0xc0000072). One occurrence is enough to alert, since this shouldn't happen at all under normal conditions.

## MITRE ATT&CK
Tactic: Defense Evasion (TA0005)
Technique: Valid Accounts (T1078)

## Triage steps
1. Confirm the account really is meant to be disabled (offboarded employee, suspended account, etc).
2. Check who or what attempted the logon, and from where.
3. Note whether the attempt used the correct password, that alone confirms the credential is still known even though the account is locked.

## Response taken (lab evidence)
Since the account was already disabled (correct state), the response focused on invalidating the credential itself. Ran `net user testuser <newpassword>` to rotate the password, then confirmed the account remained disabled via `Get-LocalUser -Name "testuser"`. This removes the known password from circulation in case it was compromised, even though the account itself stays locked.
