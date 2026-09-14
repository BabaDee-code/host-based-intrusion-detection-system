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


def test_benign_powershell_does_not_alert_on_name_alone():
    processes = [
        {
            "host": "win10-01",
            "name": "powershell.exe",
            "command_line": "powershell.exe Get-Service",
            "parent_name": "explorer.exe",
        }
    ]
    assert detect_suspicious_processes(processes) == []


def test_encoded_powershell_alerts_with_explainable_reason():
    processes = [
        {
            "host": "win10-01",
            "name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand <redacted>",
            "parent_name": "explorer.exe",
        }
    ]
    alerts = detect_suspicious_processes(processes)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SUSPICIOUS_PROCESS"
    assert alerts[0]["detection_reason"] == "suspicious_interpreter_flag:-encodedcommand"
    assert alerts[0]["parent_process"] == "explorer.exe"


def test_office_to_powershell_lineage_alerts_without_suspicious_flag():
    processes = [
        {
            "host": "win10-02",
            "name": "powershell.exe",
            "command_line": "powershell.exe Get-ChildItem",
            "parent_name": "winword.exe",
        }
    ]
    alerts = detect_suspicious_processes(processes)
    assert len(alerts) == 1
    assert alerts[0]["detection_reason"] == "suspicious_parent_child:winword.exe->powershell.exe"


def test_high_confidence_process_name_still_alerts():
    processes = [
        {"host": "linux-01", "name": "nc", "command_line": "nc -h", "parent_name": "bash"}
    ]
    alerts = detect_suspicious_processes(processes)
    assert len(alerts) == 1
    assert alerts[0]["detection_reason"] == "high_confidence_process_name"


def test_unrelated_process_with_power_shell_like_text_does_not_alert():
    processes = [
        {
            "host": "linux-01",
            "name": "python",
            "command_line": "python app.py --note=-encodedcommand",
            "parent_name": "bash",
        }
    ]
    assert detect_suspicious_processes(processes) == []
