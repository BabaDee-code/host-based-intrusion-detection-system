# Host-Based Intrusion Detection System

![CI](https://github.com/BabaDee-code/host-based-intrusion-detection-system/actions/workflows/ci.yml/badge.svg)

A custom Python-based host intrusion detection system (HIDS) portfolio project that demonstrates file integrity monitoring, context-aware process detection, authentication log analysis, baseline comparison, alert generation, and test-driven security engineering.

## What this project shows

- File integrity monitoring using cryptographic hashes
- Baseline creation and drift detection
- Context-aware process detection using process names, command-line behavior, and parent/child lineage
- False-positive reduction for legitimate administrative interpreters such as PowerShell
- Authentication log analysis for brute-force indicators
- Structured, explainable alert output for SIEM/SOAR ingestion
- Unit tests and GitHub Actions CI for trusted validation

## Repository structure

```text
src/hids/                   HIDS modules and CLI
data/                       Sample logs and process data
tests/                      Unit tests
.github/workflows/ci.yml    Automated test workflow
docs/detection-model.md     Detection design and control mapping
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements-dev.txt
pytest -q
PYTHONPATH=src python -m hids.scan data/sample_auth.log data/sample_processes.json
```

On Windows PowerShell, use `$env:PYTHONPATH = "src"` before the final command.

## Process detection approach

The process detector deliberately avoids treating PowerShell as malicious by name alone. It alerts when process telemetry provides higher-confidence context, such as encoded/hidden PowerShell execution or a high-risk parent/child relationship such as an Office application spawning PowerShell. Clearly suspicious tool names remain independently detectable.

Normalized process alerts include a `detection_reason` so an analyst can understand exactly which rule matched. See [`docs/detection-model.md`](docs/detection-model.md) for the trust model and limitations.

## Example alert

```json
{
  "alert_type": "SUSPICIOUS_PROCESS",
  "severity": "high",
  "entity": "win10-01",
  "description": "Suspicious process observed: powershell.exe",
  "detection_reason": "suspicious_interpreter_flag:-encodedcommand",
  "parent_process": "explorer.exe"
}
```

## Security controls represented

- Endpoint monitoring
- File integrity monitoring
- Log analysis
- Context-aware suspicious process detection
- Alert normalization and explainability
- Evidence-driven incident triage
- Automated test validation

## Portfolio talking points

This project demonstrates hands-on endpoint security and detection-engineering depth by implementing foundational HIDS capabilities from scratch. It is intentionally lightweight, explainable, and testable so prospective employers can review both the security logic and the software quality, including how detections are tuned to reduce false positives without weakening high-confidence signals.
