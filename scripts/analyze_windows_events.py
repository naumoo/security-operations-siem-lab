#!/usr/bin/env python3
"""Analyze synthetic Windows/Sysmon events for SOC lab detections."""

import argparse
import json
from collections import Counter
from pathlib import Path

FAILED_LOGIN = 4625
PRIVILEGE_EVENTS = {4728, 4732}
SUSPICIOUS_INTERPRETERS = ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")


def load_events(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of events")
    return data


def detect_failed_logins(events, threshold=5):
    attempts = Counter()
    for event in events:
        if event.get("event_id") == FAILED_LOGIN:
            key = (event.get("user", "unknown"), event.get("source_ip", "unknown"))
            attempts[key] += 1
    return [
        {"user": user, "source_ip": source_ip, "attempts": count, "severity": "high" if count >= 10 else "medium"}
        for (user, source_ip), count in attempts.items()
        if count >= threshold
    ]


def detect_privilege_changes(events):
    return [
        {"timestamp": e.get("timestamp"), "event_id": e.get("event_id"), "member": e.get("member_name"), "group": e.get("group_name"), "severity": "high"}
        for e in events if e.get("event_id") in PRIVILEGE_EVENTS
    ]


def detect_processes(events):
    findings = []
    for event in events:
        if event.get("event_id") != 1:
            continue
        image = event.get("image", "").lower()
        command = event.get("command_line", "").lower()
        if any(name in image for name in SUSPICIOUS_INTERPRETERS):
            indicators = [token for token in ("-enc", "downloadstring", "frombase64string") if token in command]
            findings.append({
                "timestamp": event.get("timestamp"),
                "image": event.get("image"),
                "command_line": event.get("command_line"),
                "indicators": indicators or ["command_interpreter_execution"],
                "severity": "high" if indicators else "medium",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Analyze Windows security events from a JSON file")
    parser.add_argument("input", type=Path, help="Path to JSON event data")
    args = parser.parse_args()

    events = load_events(args.input)
    report = {
        "events_analyzed": len(events),
        "failed_login_alerts": detect_failed_logins(events),
        "privilege_change_alerts": detect_privilege_changes(events),
        "process_execution_alerts": detect_processes(events),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
