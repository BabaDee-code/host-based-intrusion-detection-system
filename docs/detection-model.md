# HIDS Detection Model

## Objective

Provide a lightweight, explainable host-based intrusion detection system that can identify suspicious activity using file integrity checks, authentication logs, and process telemetry.

## Detection modules

| Module | Purpose |
|---|---|
| File integrity monitoring | Detect missing, modified, or newly created files |
| Authentication analysis | Detect repeated failed logins by user |
| Process monitoring | Detect suspicious process names and command-line flags |
| Alert normalization | Produce consistent JSON-style alert records |

## Design principles

- Keep detections explainable and auditable.
- Avoid destructive response actions.
- Produce structured alerts that can be forwarded to SIEM/SOAR tools.
- Test each detection with repeatable unit tests.

## Employer-facing explanation

This project shows practical endpoint security engineering. It demonstrates how host telemetry can be transformed into useful security alerts and how detection logic can be validated through automated tests.
