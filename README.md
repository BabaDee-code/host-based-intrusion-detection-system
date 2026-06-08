# Host-Based Intrusion Detection System

![CI](https://github.com/BabaDee-code/host-based-intrusion-detection-system/actions/workflows/ci.yml/badge.svg)

A custom Python-based host intrusion detection system (HIDS) portfolio project that demonstrates file integrity monitoring, suspicious process detection, authentication log analysis, baseline comparison, alert generation, and test-driven security engineering.

## What this project shows

- File integrity monitoring using cryptographic hashes
- Baseline creation and drift detection
- Suspicious process detection using rule-based analytics
- Authentication log analysis for brute-force indicators
- Structured alert output for SIEM/SOAR ingestion
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
python -m hids.scan data/sample_auth.log data/sample_processes.json
```

## Example alert

```json
{
  "alert_type": "AUTH_BRUTE_FORCE",
  "severity": "medium",
  "entity": "alice",
  "description": "3 failed login attempts detected"
}
```

## Security controls represented

- Endpoint monitoring
- File integrity monitoring
- Log analysis
- Suspicious process detection
- Alert normalization
- Evidence-driven incident triage
- Automated test validation

## Portfolio talking points

This project demonstrates hands-on security engineering depth by implementing foundational HIDS capabilities from scratch. It is intentionally lightweight, explainable, and testable so prospective employers can review both the security logic and the software quality.
