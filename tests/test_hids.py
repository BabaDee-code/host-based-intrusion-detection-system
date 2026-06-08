from hids.auth import detect_failed_login_bursts
from hids.fim import compare_baseline, hash_content
from hids.processes import detect_suspicious_processes


def test_failed_login_burst_detection():
    log_text = "\n".join(
        [
            "timestamp=1 user=alice event=FAILED_LOGIN",
            "timestamp=2 user=alice event=FAILED_LOGIN",
            "timestamp=3 user=alice event=FAILED_LOGIN",
        ]
    )
    alerts = detect_failed_login_bursts(log_text, threshold=3)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "AUTH_BRUTE_FORCE"
    assert alerts[0]["entity"] == "alice"


def test_file_integrity_hash_and_baseline_comparison():
    original = hash_content(b"known-good")
    modified = hash_content(b"modified")
    alerts = compare_baseline({"/etc/app.conf": original}, {"/etc/app.conf": modified})
    assert alerts == [{"alert_type": "FILE_MODIFIED", "severity": "high", "entity": "/etc/app.conf"}]


def test_suspicious_process_detection():
    processes = [
        {"host": "win10-01", "name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand <redacted>"},
        {"host": "linux-01", "name": "python", "command_line": "python app.py"},
    ]
    alerts = detect_suspicious_processes(processes)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SUSPICIOUS_PROCESS"
