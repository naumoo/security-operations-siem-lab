# Security Operations SIEM Lab

Hands-on defensive security lab focused on Windows telemetry, Splunk detection engineering, Sysmon, MITRE ATT&CK mapping, and SOC triage workflows.

## Objectives

- Ingest and analyze Windows Security and Sysmon telemetry in Splunk.
- Detect authentication anomalies, privilege changes, and suspicious process execution.
- Map detections to MITRE ATT&CK techniques.
- Provide repeatable triage playbooks for alert validation, evidence collection, severity assessment, and escalation.

## Repository Structure

```text
splunk/
  failed_logins.spl
  privilege_changes.spl
  suspicious_processes.spl
scripts/
  analyze_windows_events.py
data/
  sample_windows_events.json
playbooks/
  authentication_anomaly.md
  suspicious_process_execution.md
docs/
  mitre_mapping.md
```

## Detection Coverage

| Detection | Windows/Sysmon Event | ATT&CK | Purpose |
|---|---|---|---|
| Failed login burst | Security 4625 | T1110 | Identify repeated authentication failures |
| Privileged group membership | Security 4728/4732 | T1098 | Identify unexpected privilege changes |
| Suspicious process execution | Sysmon 1 | T1059 | Surface potentially suspicious command interpreters |

## Quick Start

1. Configure a Windows lab VM with Sysmon and forward Windows/Sysmon events to a Splunk test environment.
2. Import the SPL searches in `splunk/` and adjust the index/source fields to match your lab.
3. Use the included synthetic events to review the detection logic without requiring live telemetry.
4. Run the Python analyzer with `python scripts/analyze_windows_events.py data/sample_windows_events.json`.
5. Follow the corresponding playbook when a detection fires.

## Scope

This repository is designed for an isolated educational lab. The included event data is synthetic and contains no production credentials or private information.

## Skills Demonstrated

Splunk SPL, SIEM monitoring, Windows Event Logs, Sysmon, Python, log analysis, MITRE ATT&CK mapping, detection engineering, incident triage, and security documentation.
