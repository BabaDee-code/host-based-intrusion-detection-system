from __future__ import annotations

import json
import sys
from pathlib import Path

from .auth import detect_failed_login_bursts
from .processes import detect_suspicious_processes


def main(auth_log_path: str, processes_path: str) -> None:
    auth_log = Path(auth_log_path).read_text(encoding="utf-8")
    processes = json.loads(Path(processes_path).read_text(encoding="utf-8"))
    alerts = []
    alerts.extend(detect_failed_login_bursts(auth_log))
    alerts.extend(detect_suspicious_processes(processes))
    print(json.dumps(alerts, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python -m hids.scan data/sample_auth.log data/sample_processes.json")
    main(sys.argv[1], sys.argv[2])
