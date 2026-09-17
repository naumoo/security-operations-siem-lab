# MITRE ATT&CK Mapping

This document records the ATT&CK context used by the lab detections. Mappings describe behavior that can be consistent with a technique; an alert alone does not prove malicious activity.

| Detection | ATT&CK technique | Rationale |
|---|---|---|
| Repeated failed authentication | T1110 - Brute Force | A burst of failed logons can be consistent with password guessing or other brute-force behavior. |
| Unexpected privileged group membership | T1098 - Account Manipulation | Changes that grant additional account privileges can be consistent with account manipulation. |
| PowerShell or command interpreter execution | T1059 - Command and Scripting Interpreter | Command interpreters are frequently used for legitimate administration and can also execute attacker commands. |

## Analyst Notes

ATT&CK mappings are used to add behavioral context, not to automatically determine severity. Analysts should correlate the event with the user, host, parent process, command line, source address, expected administrative activity, and surrounding telemetry before escalation.
