import os
import yaml
import stat
import subprocess
import platform
from typing import Dict, Any, List, Optional
from lotl_edr.utils.logger import setup_logger
from lotl_edr.drift_detector.cis_level1_checks import run_all_checks as run_level1_checks

logger = setup_logger("drift_detector")

class DriftDetector:
    def __init__(self, baseline_path: str, passwd_path: Optional[str] = None, sshd_config_path: Optional[str] = None, sysctl_mock_data: Optional[Dict[str, str]] = None, suid_mock_list: Optional[List[str]] = None, permissions_mock_data: Optional[Dict[str, str]] = None):
        self.baseline_path = baseline_path
        self.passwd_path = passwd_path or "/etc/passwd"
        self.sshd_config_path = sshd_config_path or "/etc/ssh/sshd_config"
        self.sysctl_mock_data = sysctl_mock_data
        self.suid_mock_list = suid_mock_list
        self.permissions_mock_data = permissions_mock_data
        self.baseline: Dict[str, Any] = {}
        self.load_baseline()

    def load_baseline(self) -> None:
        if not os.path.exists(self.baseline_path):
            logger.error(f"Baseline file {self.baseline_path} not found.")
            return

        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                self.baseline = yaml.safe_load(f) or {}
            logger.info("Loaded CIS baseline settings successfully.")
        except Exception as e:
            logger.error(f"Failed to parse baseline settings: {e}")

    def check_drift(self) -> Dict[str, Any]:
        violations: List[Dict[str, Any]] = []

        sshd_baseline = self.baseline.get("sshd_config", {})
        sysctl_baseline = self.baseline.get("sysctl", {})
        perm_baseline = self.baseline.get("file_permissions", {})

        passwd_baseline = self.baseline.get("passwd_users", [])
        suid_baseline = self.baseline.get("suid_binaries", [])
        total_checks = (len(sshd_baseline) + len(sysctl_baseline) + len(perm_baseline)
                        + len(passwd_baseline) + len(suid_baseline) + 2)

        self._audit_passwd(violations)
        self._audit_sshd(violations)
        self._audit_file_permissions(violations)
        self._audit_sysctl(violations)
        self._audit_suid(violations)

        # Additional broad Level 1 coverage (process hardening, AppArmor,
        # banners, network sysctl, firewall, logging, auditd config,
        # cron, expanded SSH directives, PAM/pwquality, user accounts).
        # NOTE: still not full parity with CIS-CAT Pro's 246 scored
        # controls -- this is a broader continuous monitor, not a
        # replacement for periodic authoritative CIS-CAT assessment.
        try:
            level1_violations, level1_checks_run = run_level1_checks()
            violations.extend(level1_violations)
            total_checks += level1_checks_run
        except Exception as e:
            logger.error(f"Error running Level 1 checks: {e}")

        drift_count = len(violations)
        drift_percent = min(100.0, (drift_count / total_checks) * 100.0) if total_checks > 0 else 0.0
        compliance_percent = 100.0 - drift_percent

        report = {
            "compliance_percent": round(compliance_percent, 2),
            "drift_percent": round(drift_percent, 2),
            "drift_count": drift_count,
            "total_checks": total_checks,
            "violations": violations
        }

        logger.info(f"Drift check complete. Compliance: {report['compliance_percent']}% | Drift Violations: {drift_count}")
        return report

    def is_drift_active(self) -> bool:
        report = self.check_drift()
        for v in report["violations"]:
            if v["severity"] in ["medium", "high", "critical"]:
                return True
        return False

    def _audit_passwd(self, violations: List[Dict[str, Any]]) -> None:
        expected_users = set(self.baseline.get("passwd_users", []))
        if not expected_users:
            return

        current_users = set()
        if os.path.exists(self.passwd_path):
            try:
                with open(self.passwd_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(":")
                        if parts and parts[0]:
                            current_users.add(parts[0])
            except Exception as e:
                logger.error(f"Failed to read passwd file {self.passwd_path}: {e}")
                return
        else:
            current_users = expected_users.copy()

        added_users = current_users - expected_users
        for user in added_users:
            violations.append({
                "entity": "passwd", "drift_type": "ADDED",
                "details": f"Unauthorized account '{user}' found in passwd.",
                "severity": "high", "affected_control": "CIS 6.2.1",
                "recommended_remediation": f"Delete the unauthorized user account: 'userdel {user}'"
            })

        removed_users = expected_users - current_users
        for user in removed_users:
            violations.append({
                "entity": "passwd", "drift_type": "REMOVED",
                "details": f"Expected system account '{user}' is missing.",
                "severity": "medium", "affected_control": "CIS 6.2.1",
                "recommended_remediation": f"Restore default system account: 'useradd {user}'"
            })

    def _audit_sshd(self, violations: List[Dict[str, Any]]) -> None:
        expected_settings = self.baseline.get("sshd_config", {})
        if not expected_settings:
            return

        current_settings = {}
        if os.path.exists(self.sshd_config_path):
            try:
                with open(self.sshd_config_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            key = parts[0].strip()
                            val = parts[1].strip().strip('"').strip("'")
                            current_settings[key] = val
            except Exception as e:
                logger.error(f"Failed to read sshd config {self.sshd_config_path}: {e}")
                return

        for key, expected_val in expected_settings.items():
            current_val = current_settings.get(key)
            if current_val is None:
                violations.append({
                    "entity": f"sshd_config.{key}", "drift_type": "MODIFIED",
                    "details": f"SSH parameter '{key}' is not explicitly defined in sshd_config. Secure baseline expects '{expected_val}'.",
                    "severity": "medium", "affected_control": "CIS 5.2.1",
                    "recommended_remediation": f"Add directive '{key} {expected_val}' to {self.sshd_config_path} and restart sshd."
                })
            elif current_val.lower() != expected_val.lower():
                violations.append({
                    "entity": f"sshd_config.{key}", "drift_type": "MODIFIED",
                    "details": f"SSH parameter '{key}' is set to '{current_val}'. Secure baseline expects '{expected_val}'.",
                    "severity": "critical", "affected_control": "CIS 5.2.1",
                    "recommended_remediation": f"Change directive to '{key} {expected_val}' in {self.sshd_config_path} and restart sshd."
                })

    def _audit_file_permissions(self, violations: List[Dict[str, Any]]) -> None:
        expected_perms = self.baseline.get("file_permissions", {})
        if not expected_perms:
            return

        for filepath, expected_octal in expected_perms.items():
            if self.permissions_mock_data and filepath in self.permissions_mock_data:
                current_octal = self.permissions_mock_data[filepath]
            else:
                if os.path.exists(filepath):
                    try:
                        mode = os.stat(filepath).st_mode
                        current_octal = f"{stat.S_IMODE(mode):o}"
                    except Exception as e:
                        logger.error(f"Failed to check permissions on {filepath}: {e}")
                        continue
                else:
                    continue

            if current_octal != expected_octal:
                violations.append({
                    "entity": f"permissions.{filepath}", "drift_type": "MODIFIED",
                    "details": f"Permissions on {filepath} are set to {current_octal}. Secure baseline expects {expected_octal}.",
                    "severity": "high", "affected_control": "CIS 6.1.2",
                    "recommended_remediation": f"Restore secure permissions: 'chmod {expected_octal} {filepath}'"
                })

    def _audit_sysctl(self, violations: List[Dict[str, Any]]) -> None:
        expected_sysctl = self.baseline.get("sysctl", {})
        if not expected_sysctl:
            return

        for key, expected_val in expected_sysctl.items():
            current_val = None

            if self.sysctl_mock_data and key in self.sysctl_mock_data:
                current_val = self.sysctl_mock_data[key]
            else:
                if platform.system() == "Linux":
                    try:
                        res = subprocess.run(f"sysctl -n {key}", shell=True, capture_output=True, text=True)
                        if res.returncode == 0:
                            current_val = res.stdout.strip()
                    except Exception:
                        pass

            if current_val is None:
                continue

            if current_val != expected_val:
                violations.append({
                    "entity": f"sysctl.{key}", "drift_type": "MODIFIED",
                    "details": f"Kernel parameter '{key}' is set to '{current_val}'. Secure baseline expects '{expected_val}'.",
                    "severity": "medium", "affected_control": "CIS 1.1.1",
                    "recommended_remediation": f"Set parameter: 'sysctl -w {key}={expected_val}' and write to /etc/sysctl.conf."
                })

    def _audit_suid(self, violations: List[Dict[str, Any]]) -> None:
        expected_suid = self.baseline.get("suid_binaries", [])
        if not expected_suid:
            return

        current_suid = []
        if self.suid_mock_list is not None:
            current_suid = self.suid_mock_list
        else:
            if platform.system() == "Linux":
                scan_dir = "/usr/bin"
                if os.path.exists(scan_dir):
                    try:
                        for filename in os.listdir(scan_dir):
                            filepath = os.path.join(scan_dir, filename)
                            try:
                                mode = os.stat(filepath).st_mode
                                if mode & stat.S_ISUID:
                                    current_suid.append(filepath)
                            except Exception:
                                pass
                    except Exception:
                        pass
            else:
                current_suid = expected_suid.copy()

        added_suid = set(current_suid) - set(expected_suid)
        for filepath in added_suid:
            violations.append({
                "entity": "suid_binary", "drift_type": "ADDED",
                "details": f"Unauthorized SUID binary found: {filepath}",
                "severity": "high", "affected_control": "CIS 6.1.10",
                "recommended_remediation": f"Remove SUID permissions from binary: 'chmod u-s {filepath}'"
            })
