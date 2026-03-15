from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from driftwatch.app.rules.base import FindingDraft, RuleDefinition


TEMP_MARKERS = ("/tmp", "/dev/shm", "/var/tmp", "\\temp\\", "\\appdata\\local\\temp\\", "/library/caches")
KERNEL_LIKE_NAMES = ("kworker", "ksoftirqd", "kthreadd", "migration", "rcu")
SERVICE_USERS = ("www-data", "nginx", "apache", "http", "nobody", "localservice", "networkservice")
POWERSHELL_FLAGS = ("-enc", "-encodedcommand", "-nop", "-w hidden", "-windowstyle hidden")


def _path_in_temp(path_value: str) -> bool:
    lowered = path_value.lower()
    return any(marker in lowered for marker in TEMP_MARKERS)


def _recent_epoch(epoch_value: float | None, days: int = 7) -> bool:
    if not epoch_value:
        return False
    modified_at = datetime.fromtimestamp(epoch_value, tz=timezone.utc)
    return modified_at >= datetime.now(timezone.utc) - timedelta(days=days)


def suspicious_temp_process(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for process in snapshot.get("collectors", {}).get("processes", {}).get("records", []):
        exe = process.get("exe") or ""
        cwd = process.get("cwd") or ""
        cmdline = " ".join(process.get("cmdline") or [])
        if _path_in_temp(exe) or _path_in_temp(cwd) or _path_in_temp(cmdline):
            findings.append(
                FindingDraft(
                    category="Suspicious processes",
                    severity="high",
                    title=f"Process executing from a temporary location: {process.get('name') or process.get('pid')}",
                    description="Processes launched from temp or cache paths deserve review because they bypass normal deployment paths.",
                    evidence=process,
                    rule_name="suspicious_temp_process",
                    os_family=os_family,
                    source_module="rules.processes",
                    confidence="high",
                )
            )
    return findings


def fake_kernel_process(snapshot: dict, os_family: str) -> list[FindingDraft]:
    if os_family != "linux":
        return []
    findings: list[FindingDraft] = []
    for process in snapshot.get("collectors", {}).get("processes", {}).get("records", []):
        name = (process.get("name") or "").lower()
        username = (process.get("username") or "").lower()
        if any(name.startswith(prefix) for prefix in KERNEL_LIKE_NAMES) and username not in {"root", ""}:
            findings.append(
                FindingDraft(
                    category="Suspicious processes",
                    severity="high",
                    title=f"Kernel-like process name under non-root account: {process.get('name')}",
                    description="Linux kernel worker names normally do not run as regular user-space processes.",
                    evidence=process,
                    rule_name="fake_kernel_process",
                    os_family=os_family,
                    source_module="rules.processes",
                    confidence="medium",
                )
            )
    return findings


def outbound_ssh_burst(snapshot: dict, os_family: str) -> list[FindingDraft]:
    network_records = snapshot.get("collectors", {}).get("network", {}).get("records", [])
    burst = [entry for entry in network_records if entry.get("rport") == 22 and entry.get("status") == "ESTABLISHED"]
    if len(burst) < 4:
        return []
    return [
        FindingDraft(
            category="Network anomalies",
            severity="medium",
            title="Multiple established outbound SSH sessions detected",
            description="A burst of outbound SSH traffic can be benign for administrators, but it also appears in lateral movement and scripted collection workflows.",
            evidence={"count": len(burst), "connections": burst[:12]},
            rule_name="outbound_ssh_burst",
            os_family=os_family,
            source_module="rules.network",
            confidence="medium",
        )
    ]


def suspicious_persistence(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for entry in snapshot.get("collectors", {}).get("persistence", {}).get("records", []):
        path_value = (entry.get("path") or "") + " " + (entry.get("command") or "")
        if _path_in_temp(path_value):
            findings.append(
                FindingDraft(
                    category="Persistence checks",
                    severity="high" if os_family == "windows" else "medium",
                    title=f"Persistence entry references temp or cache path: {entry.get('name')}",
                    description="Startup entries should rarely point into temporary or user-cache locations.",
                    evidence=entry,
                    rule_name="suspicious_persistence",
                    os_family=os_family,
                    source_module="rules.persistence",
                    confidence="high",
                )
            )
    return findings


def recent_authorized_keys(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for record in snapshot.get("collectors", {}).get("filesystem", {}).get("records", []):
        if record.get("category") == "authorized_keys" and _recent_epoch(record.get("mtime"), days=7):
            findings.append(
                FindingDraft(
                    category="Unauthorized key or startup file changes",
                    severity="medium",
                    title="Recently modified authorized_keys file",
                    description="Authorized key changes are often legitimate, but they should be attributable to an expected administrator action.",
                    evidence=record,
                    rule_name="recent_authorized_keys",
                    os_family=os_family,
                    source_module="rules.filesystem",
                    confidence="medium",
                )
            )
    return findings


def recent_sensitive_files(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for record in snapshot.get("collectors", {}).get("filesystem", {}).get("records", []):
        if record.get("category") != "recent_sensitive_file":
            continue
        if not _recent_epoch(record.get("mtime"), days=7):
            continue
        findings.append(
            FindingDraft(
                category="Recently modified sensitive files",
                severity="low",
                title=f"Recently modified sensitive path: {record.get('path')}",
                description="Sensitive paths changed recently. Treat this as a review prompt rather than a compromise claim.",
                evidence=record,
                rule_name="recent_sensitive_files",
                os_family=os_family,
                source_module="rules.filesystem",
                confidence="low",
            )
        )
    return findings


def deleted_running_executable(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for process in snapshot.get("collectors", {}).get("processes", {}).get("records", []):
        exe = process.get("exe") or ""
        if not exe:
            continue
        if exe.endswith(" (deleted)") or (os.path.isabs(exe) and not os.path.exists(exe) and os_family != "windows"):
            findings.append(
                FindingDraft(
                    category="Suspicious processes",
                    severity="high",
                    title=f"Process binary is missing on disk: {process.get('name')}",
                    description="A running process whose executable path no longer exists should be reviewed because it may indicate replaced or deleted binaries.",
                    evidence=process,
                    rule_name="deleted_running_executable",
                    os_family=os_family,
                    source_module="rules.processes",
                    confidence="medium",
                )
            )
    return findings


def hidden_files(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for record in snapshot.get("collectors", {}).get("filesystem", {}).get("records", []):
        if record.get("category") != "hidden_file":
            continue
        findings.append(
            FindingDraft(
                category="Hidden files in suspicious locations",
                severity="medium",
                title=f"Hidden file in a startup or temp path: {record.get('path')}",
                description="Hidden files in temporary or auto-start locations deserve validation because they reduce analyst visibility.",
                evidence=record,
                rule_name="hidden_files",
                os_family=os_family,
                source_module="rules.filesystem",
                confidence="medium",
            )
        )
    return findings


def powershell_encoded(snapshot: dict, os_family: str) -> list[FindingDraft]:
    if os_family != "windows":
        return []
    findings: list[FindingDraft] = []
    for process in snapshot.get("collectors", {}).get("processes", {}).get("records", []):
        name = (process.get("name") or "").lower()
        cmdline = " ".join(process.get("cmdline") or []).lower()
        if name not in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
            continue
        if any(flag in cmdline for flag in POWERSHELL_FLAGS):
            findings.append(
                FindingDraft(
                    category="Suspicious processes",
                    severity="high",
                    title="PowerShell launched with encoded or hidden execution flags",
                    description="PowerShell flags such as encoded commands and hidden windows often appear in administrative automation, but they also match common abuse patterns.",
                    evidence=process,
                    rule_name="powershell_encoded",
                    os_family=os_family,
                    source_module="rules.processes",
                    confidence="high",
                )
            )
    return findings


def service_account_user_writable(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for process in snapshot.get("collectors", {}).get("processes", {}).get("records", []):
        username = (process.get("username") or "").lower()
        exe = process.get("exe") or ""
        if username and any(account in username for account in SERVICE_USERS) and _path_in_temp(exe):
            findings.append(
                FindingDraft(
                    category="Service account abuse patterns",
                    severity="high",
                    title=f"Service account process running from a writable path: {process.get('name')}",
                    description="Service-style accounts should not normally execute binaries from temporary or cache directories.",
                    evidence=process,
                    rule_name="service_account_user_writable",
                    os_family=os_family,
                    source_module="rules.processes",
                    confidence="medium",
                )
            )
    return findings


def baseline_drift(snapshot: dict, os_family: str) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for item in snapshot.get("baseline_diff", []):
        severity = "medium" if item.get("baseline_type") in {"persistence_entry", "authorized_key"} else "low"
        findings.append(
            FindingDraft(
                category="Baseline drift",
                severity=severity,
                title=f"Baseline drift detected for {item.get('item_key')}",
                description="The current scan differs from the stored local baseline. Review whether the change is expected before updating the baseline.",
                evidence=item,
                rule_name="baseline_drift",
                os_family=os_family,
                source_module="rules.baseline",
                confidence="medium",
            )
        )
    return findings


RULE_REGISTRY: list[tuple[RuleDefinition, callable]] = [
    (
        RuleDefinition(
            name="suspicious_temp_process",
            description="Flags processes executing from temp or cache paths.",
            category="Suspicious processes",
            supported_os={"linux", "macos", "windows"},
            severity_hint="high",
        ),
        suspicious_temp_process,
    ),
    (
        RuleDefinition(
            name="fake_kernel_process",
            description="Detects user-space process names that mimic Linux kernel workers.",
            category="Suspicious processes",
            supported_os={"linux"},
            severity_hint="high",
        ),
        fake_kernel_process,
    ),
    (
        RuleDefinition(
            name="outbound_ssh_burst",
            description="Looks for multiple established outbound SSH sessions.",
            category="Network anomalies",
            supported_os={"linux", "macos", "windows"},
            severity_hint="medium",
        ),
        outbound_ssh_burst,
    ),
    (
        RuleDefinition(
            name="suspicious_persistence",
            description="Flags startup entries pointing to temp or cache locations.",
            category="Persistence checks",
            supported_os={"linux", "macos", "windows"},
            severity_hint="medium",
        ),
        suspicious_persistence,
    ),
    (
        RuleDefinition(
            name="recent_authorized_keys",
            description="Highlights recently modified authorized_keys files.",
            category="Unauthorized key or startup file changes",
            supported_os={"linux", "macos", "windows"},
            severity_hint="medium",
        ),
        recent_authorized_keys,
    ),
    (
        RuleDefinition(
            name="recent_sensitive_files",
            description="Flags recent changes under configured sensitive paths.",
            category="Recently modified sensitive files",
            supported_os={"linux", "macos", "windows"},
            severity_hint="low",
        ),
        recent_sensitive_files,
    ),
    (
        RuleDefinition(
            name="deleted_running_executable",
            description="Detects running processes whose executable no longer exists on disk.",
            category="Suspicious processes",
            supported_os={"linux", "macos", "windows"},
            severity_hint="high",
        ),
        deleted_running_executable,
    ),
    (
        RuleDefinition(
            name="hidden_files",
            description="Flags hidden files in temp and startup locations.",
            category="Hidden files in suspicious locations",
            supported_os={"linux", "macos", "windows"},
            severity_hint="medium",
        ),
        hidden_files,
    ),
    (
        RuleDefinition(
            name="powershell_encoded",
            description="Looks for PowerShell launched with encoded or hidden flags.",
            category="Suspicious processes",
            supported_os={"windows"},
            severity_hint="high",
        ),
        powershell_encoded,
    ),
    (
        RuleDefinition(
            name="service_account_user_writable",
            description="Flags service-account processes executing from writable temp paths.",
            category="Service account abuse patterns",
            supported_os={"linux", "macos", "windows"},
            severity_hint="high",
        ),
        service_account_user_writable,
    ),
    (
        RuleDefinition(
            name="baseline_drift",
            description="Compares current startup and key material to the stored local baseline.",
            category="Baseline drift",
            supported_os={"linux", "macos", "windows"},
            severity_hint="medium",
        ),
        baseline_drift,
    ),
]
