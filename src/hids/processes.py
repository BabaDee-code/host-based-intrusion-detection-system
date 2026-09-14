from __future__ import annotations

from typing import Any

HIGH_CONFIDENCE_PROCESS_NAMES = {"nc", "netcat", "mimikatz.exe"}
SCRIPT_INTERPRETERS = {"powershell.exe", "pwsh", "pwsh.exe"}
SUSPICIOUS_FLAGS = ("-enc", "-encodedcommand", "-nop", "-w hidden")
SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("w3wp.exe", "powershell.exe"),
    ("winword.exe", "pwsh.exe"),
    ("excel.exe", "pwsh.exe"),
    ("outlook.exe", "pwsh.exe"),
    ("w3wp.exe", "pwsh.exe"),
}


def detect_suspicious_processes(processes: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Detect suspicious processes using explainable name, argument, and lineage rules.

    Legitimate administrative interpreters such as PowerShell are not considered
    suspicious solely because of their process name. They require suspicious
    command-line behavior or a high-risk parent/child relationship.
    """
    alerts: list[dict[str, str]] = []

    for process in processes:
        name = str(process.get("name", "")).lower()
        command_line = str(process.get("command_line", "")).lower()
        host = str(process.get("host", "unknown"))
        parent_name = str(process.get("parent_name", "")).lower()

        reason = _detection_reason(name, command_line, parent_name)
        if reason is None:
            continue

        alert = {
            "alert_type": "SUSPICIOUS_PROCESS",
            "severity": "high",
            "entity": host,
            "description": f"Suspicious process observed: {process.get('name', 'unknown')}",
            "detection_reason": reason,
        }
        if parent_name:
            alert["parent_process"] = parent_name
        alerts.append(alert)

    return alerts


def _detection_reason(name: str, command_line: str, parent_name: str) -> str | None:
    if name in HIGH_CONFIDENCE_PROCESS_NAMES:
        return "high_confidence_process_name"

    if name in SCRIPT_INTERPRETERS:
        matched_flag = next((flag for flag in SUSPICIOUS_FLAGS if flag in command_line), None)
        if matched_flag:
            return f"suspicious_interpreter_flag:{matched_flag}"

    if (parent_name, name) in SUSPICIOUS_PARENT_CHILD:
        return f"suspicious_parent_child:{parent_name}->{name}"

    return None
