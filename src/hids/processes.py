from __future__ import annotations

from typing import Any

SUSPICIOUS_PROCESS_NAMES = {"nc", "netcat", "mimikatz.exe", "powershell.exe"}
SUSPICIOUS_FLAGS = {"-enc", "-encodedcommand", "-nop", "-w hidden"}


def detect_suspicious_processes(processes: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Detect suspicious processes using simple, explainable rules."""
    alerts: list[dict[str, str]] = []

    for process in processes:
        name = str(process.get("name", "")).lower()
        command_line = str(process.get("command_line", "")).lower()
        host = str(process.get("host", "unknown"))

        if name in SUSPICIOUS_PROCESS_NAMES or any(flag in command_line for flag in SUSPICIOUS_FLAGS):
            alerts.append(
                {
                    "alert_type": "SUSPICIOUS_PROCESS",
                    "severity": "high",
                    "entity": host,
                    "description": f"Suspicious process observed: {process.get('name', 'unknown')}",
                }
            )

    return alerts
