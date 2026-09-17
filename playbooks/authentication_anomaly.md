# Authentication Anomaly Triage Playbook

## Trigger
Five or more failed Windows logons associated with the same account and source address in a short analysis window.

## Triage
1. Confirm the source event is Windows Security Event ID 4625 and validate the timestamp, account, host, logon type, and source address.
2. Determine whether the source belongs to expected lab infrastructure or an approved administrative workflow.
3. Search for a successful Event ID 4624 for the same account/source near the failed attempts.
4. Review other authentication failures from the same source and failures affecting other accounts.
5. Correlate with endpoint telemetry for unusual process execution or account/privilege changes.

## Severity Guidance
- Low: small number of failures with an obvious benign explanation.
- Medium: threshold exceeded without evidence of successful access.
- High: failures followed by unexpected successful authentication, privilege change, or suspicious endpoint activity.

## Evidence to Preserve
Raw events, search time range, account, host, source address, related successful logons, process telemetry, and analyst notes.

## Escalation
Escalate when the activity cannot be explained by expected lab behavior or when correlated events suggest unauthorized access. Document the evidence and reasoning rather than relying on the alert count alone.
