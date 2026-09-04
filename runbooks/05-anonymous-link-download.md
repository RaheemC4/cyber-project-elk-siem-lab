# Runbook: Anonymous Link Used for Download - T1567.002

## What this detects
Use of an anonymous (unauthenticated) sharing link to download a file from SharePoint or OneDrive, sourced from the Microsoft 365 unified audit log (`AnonymousLinkUsed` operation). Bypasses normal access controls and may indicate data exfiltration.

## MITRE ATT&CK
Tactic: Exfiltration (TA0010)
Technique: Exfiltration Over Web Service (T1567), Sub-technique: Exfiltration to Cloud Storage (T1567.002)

## Triage steps
1. Identify which file was shared and whether it's sensitive.
2. Check who created the anonymous link and whether that's normal for their role.
3. Check how many times the link has been used and from where.

## Response (documented, not executed live)
This alert type could not be reproduced or actioned live, as it requires a real Microsoft 365 tenant, outside the scope of a local lab. In production, the response would be to revoke the specific anonymous sharing link via the SharePoint admin center or Microsoft Graph API, force re-authentication for any future access, and review the file's other sharing permissions for further exposure. The detection rule and simulated event were built against Microsoft's documented event schema for this exact scenario, but the response step here is a documented procedure rather than an executed action, a deliberate and defensible distinction to raise in an interview.
