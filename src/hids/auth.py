from __future__ import annotations

from collections import Counter


def detect_failed_login_bursts(log_text: str, threshold: int = 3) -> list[dict[str, str | int]]:
    """Detect repeated failed login attempts by username from simple auth logs."""
    failures: Counter[str] = Counter()

    for line in log_text.splitlines():
        if "FAILED_LOGIN" not in line:
            continue
        parts = dict(item.split("=", 1) for item in line.split() if "=" in item)
        username = parts.get("user", "unknown")
        failures[username] += 1

    alerts = []
    for username, count in failures.items():
        if count >= threshold:
            alerts.append(
                {
                    "alert_type": "AUTH_BRUTE_FORCE",
                    "severity": "medium",
                    "entity": username,
                    "event_count": count,
                    "description": f"{count} failed login attempts detected",
                }
            )
    return alerts
