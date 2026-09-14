# HIDS Detection Model

## Objective

Provide a lightweight, explainable host-based intrusion detection system that can identify suspicious activity using file integrity checks, authentication logs, and process telemetry.

## Detection modules

| Module | Purpose |
|---|---|
| File integrity monitoring | Detect missing, modified, or newly created files |
| Authentication analysis | Detect repeated failed logins by user |
| Process monitoring | Detect suspicious tools, interpreter behavior, and high-risk process lineage |
| Alert normalization | Produce consistent JSON-style alert records |

## Process detection model

Process-name-only detection is intentionally limited to higher-confidence tools such as `nc`, `netcat`, and `mimikatz.exe`. Legitimate administrative interpreters such as PowerShell are not treated as malicious simply because they execute.

PowerShell and PowerShell Core require additional behavioral context before an alert is generated:

- suspicious interpreter arguments such as encoded commands, no-profile execution, or hidden windows; or
- high-risk parent/child relationships, such as Microsoft Office applications or IIS worker processes spawning PowerShell.

Each process alert includes a `detection_reason` so an analyst can distinguish a process-name match from a suspicious argument or lineage match. When parent telemetry is present, the normalized alert also includes `parent_process`.

### Why this matters

A detection that alerts on every PowerShell execution creates avoidable analyst noise in environments where administrators and automation legitimately use PowerShell. Requiring behavioral context improves signal quality without suppressing encoded/hidden execution or suspicious process lineage. The rules remain deterministic and auditable rather than relying on opaque scoring.

### Limitations

- This project consumes simplified process telemetry and does not inspect process ancestry beyond the immediate parent.
- Command-line matching is intentionally narrow and should be tuned against environment-specific baselines before production use.
- The detector identifies suspicious activity; it does not perform automatic containment or destructive response actions.

## Design principles

- Keep detections explainable and auditable.
- Prefer behavioral context over noisy process-name-only rules where legitimate administration is common.
- Avoid destructive response actions.
- Produce structured alerts that can be forwarded to SIEM/SOAR tools.
- Test positive detections and expected benign behavior with repeatable unit tests.

## Employer-facing explanation

This project shows practical endpoint security and detection engineering. It demonstrates how host telemetry can be transformed into useful security alerts, how false-positive pressure influences rule design, and how detection logic can be validated through automated tests.
