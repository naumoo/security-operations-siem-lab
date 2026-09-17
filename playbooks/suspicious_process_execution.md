# Suspicious Process Execution Triage Playbook

## Trigger
Sysmon Event ID 1 involving PowerShell, cmd, wscript, or cscript, with additional attention to encoded or download-related command-line indicators.

## Validation
Confirm the executable path, command line, user, parent process, host, and timestamp. Command interpreters are common administrative tools, so their presence alone is not proof of malicious behavior.

## Investigation
1. Review the parent/child process chain.
2. Compare the command with expected administrative or user activity.
3. Search nearby Sysmon and Windows Security events for network connections, authentication activity, and privilege changes.
4. Identify suspicious command-line indicators such as encoded arguments or unexpected download behavior.
5. Preserve the original event and correlated telemetry.

## Escalation
Escalate when execution is unexplained and supported by additional suspicious context, such as an unusual parent process, unexpected account, encoded command, or correlated authentication/privilege activity.
