from __future__ import annotations

import hashlib


def hash_content(content: bytes) -> str:
    """Return a SHA-256 hash for file integrity monitoring."""
    return hashlib.sha256(content).hexdigest()


def compare_baseline(baseline: dict[str, str], current: dict[str, str]) -> list[dict[str, str]]:
    """Compare known-good file hashes to current file hashes."""
    alerts: list[dict[str, str]] = []

    for path, expected_hash in baseline.items():
        actual_hash = current.get(path)
        if actual_hash is None:
            alerts.append({"alert_type": "FILE_MISSING", "severity": "high", "entity": path})
        elif actual_hash != expected_hash:
            alerts.append({"alert_type": "FILE_MODIFIED", "severity": "high", "entity": path})

    for path in current.keys() - baseline.keys():
        alerts.append({"alert_type": "FILE_CREATED", "severity": "medium", "entity": path})

    return alerts
