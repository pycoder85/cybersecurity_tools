from driftwatch.app.rules.engine import evaluate_rules


def test_rule_engine_flags_temp_process_and_baseline_drift():
    snapshot = {
        "collectors": {
            "processes": {
                "records": [
                    {
                        "pid": 101,
                        "name": "python",
                        "username": "www-data",
                        "exe": "/tmp/payload",
                        "cmdline": ["/tmp/payload"],
                        "cwd": "/tmp",
                    }
                ]
            },
            "network": {"records": []},
            "filesystem": {"records": []},
            "persistence": {"records": []},
        },
        "baseline_diff": [{"change": "new", "baseline_type": "startup_file", "item_key": "/etc/systemd/system/demo.service"}],
    }

    findings = evaluate_rules(snapshot, "linux")
    rule_names = {finding.rule_name for finding in findings}

    assert "suspicious_temp_process" in rule_names
    assert "baseline_drift" in rule_names


def test_rule_engine_flags_windows_powershell_encoded_command():
    snapshot = {
        "collectors": {
            "processes": {
                "records": [
                    {
                        "pid": 204,
                        "name": "powershell.exe",
                        "username": "user",
                        "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "cmdline": ["powershell.exe", "-enc", "SQBmAG8AbwA="],
                        "cwd": r"C:\Users\alice",
                    }
                ]
            },
            "network": {"records": []},
            "filesystem": {"records": []},
            "persistence": {"records": []},
        },
        "baseline_diff": [],
    }

    findings = evaluate_rules(snapshot, "windows")

    assert any(finding.rule_name == "powershell_encoded" for finding in findings)
