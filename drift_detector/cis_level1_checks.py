"""
CS2 — CIS Ubuntu 24.04 LTS Level 1 Benchmark Checker

Covers major Level 1 sections from the official CIS Ubuntu 24.04 Benchmark:
  1.5  Additional Process Hardening
  1.6  Mandatory Access Control (AppArmor)
  1.7  Command Line Warning Banners
  3.2  Network Parameters (Host Only)
  3.3  Network Parameters (Host and Router)
  3.5  Firewall Configuration (ufw)
  4.1  Configure Logging (rsyslog/journald)
  4.2  Configure auditd
  5.1  Configure cron
  5.2  Configure SSH Server
  5.3  Configure PAM / pwquality / faillock
  5.4  User Accounts and Environment

NOT covered (would need per-package/per-service deep logic CIS-CAT's
licensed engine has purpose-built for): 1.1 filesystem partition layout,
2.x exhaustive service-by-service audit, 6.x file permission recursive
scans across the whole filesystem. This checker is a genuine expansion
of coverage, not a full CIS-CAT replacement -- treat its "compliance %"
as a broader, but still non-authoritative, continuous monitor. CIS-CAT
Pro results remain the source of truth for official compliance.

Returns a list of violation dicts matching the existing DriftDetector
schema: entity, drift_type, details, severity, affected_control,
recommended_remediation. Also returns total_checks_run for percentage
calculation.
"""

import os
import re
import subprocess
import stat as stat_module


def _run(cmd, timeout=5):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return res.stdout.strip(), res.returncode
    except Exception:
        return "", 1


def _add(violations, entity, details, severity, control, remediation, drift_type="MODIFIED"):
    violations.append({
        "entity": entity,
        "drift_type": drift_type,
        "details": details,
        "severity": severity,
        "affected_control": control,
        "recommended_remediation": remediation,
    })


def check_process_hardening(violations, checks_run):
    """1.5 Additional Process Hardening"""
    checks_run[0] += 1
    out, _ = _run("sysctl -n kernel.randomize_va_space 2>/dev/null")
    if out != "2":
        _add(violations, "process_hardening.aslr", f"ASLR (kernel.randomize_va_space) is '{out}', expected '2'",
             "high", "CIS 1.5.1", "sysctl -w kernel.randomize_va_space=2 (persist in /etc/sysctl.d/)")

    checks_run[0] += 1
    out, _ = _run("sysctl -n fs.suid_dumpable 2>/dev/null")
    if out != "0":
        _add(violations, "process_hardening.suid_dumpable", f"fs.suid_dumpable is '{out}', expected '0'",
             "medium", "CIS 1.5.2", "sysctl -w fs.suid_dumpable=0")

    checks_run[0] += 1
    limits_out, _ = _run("grep -r 'hard core' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
    if not limits_out:
        _add(violations, "process_hardening.core_dumps", "No 'hard core 0' restriction found in limits.conf",
             "medium", "CIS 1.5.3", "Add '* hard core 0' to /etc/security/limits.conf")

    checks_run[0] += 1
    out, _ = _run("sysctl -n kernel.yama.ptrace_scope 2>/dev/null")
    if out not in ("1", "2", "3"):
        _add(violations, "process_hardening.ptrace_scope", f"kernel.yama.ptrace_scope is '{out}', expected >=1",
             "medium", "CIS 1.5.4", "sysctl -w kernel.yama.ptrace_scope=1")


def check_apparmor(violations, checks_run):
    """1.6 Mandatory Access Control"""
    checks_run[0] += 1
    out, rc = _run("systemctl is-enabled apparmor 2>/dev/null")
    if rc != 0 or "enabled" not in out:
        _add(violations, "mac.apparmor_enabled", "AppArmor service is not enabled",
             "critical", "CIS 1.6.1", "systemctl --now enable apparmor")

    checks_run[0] += 1
    out, _ = _run("aa-status --enforced 2>/dev/null | wc -l")
    try:
        if int(out or 0) == 0:
            _add(violations, "mac.apparmor_profiles", "No AppArmor profiles in enforce mode",
                 "high", "CIS 1.6.2", "Set profiles to enforce mode via aa-enforce")
    except ValueError:
        pass


def check_banners(violations, checks_run):
    """1.7 Command Line Warning Banners"""
    for banner_file, control in [("/etc/issue", "CIS 1.7.1"), ("/etc/issue.net", "CIS 1.7.2"), ("/etc/motd", "CIS 1.7.5")]:
        checks_run[0] += 1
        if not os.path.exists(banner_file):
            _add(violations, f"banners.{os.path.basename(banner_file)}", f"{banner_file} does not exist",
                 "low", control, f"Create {banner_file} with an authorized-access-only warning")
            continue
        try:
            with open(banner_file) as f:
                content = f.read()
            if re.search(r"\\v|\\r|\\m|\\s|ubuntu|linux", content, re.IGNORECASE):
                _add(violations, f"banners.{os.path.basename(banner_file)}", f"{banner_file} contains OS/version identifiers",
                     "low", control, f"Remove OS version strings from {banner_file}")
        except Exception:
            pass

    for banner_file, control in [("/etc/issue", "CIS 1.7.3"), ("/etc/issue.net", "CIS 1.7.4"), ("/etc/motd", "CIS 1.7.6")]:
        checks_run[0] += 1
        if os.path.exists(banner_file):
            mode = oct(stat_module.S_IMODE(os.stat(banner_file).st_mode))[2:]
            if mode not in ("644", "600"):
                _add(violations, f"banners.{os.path.basename(banner_file)}_perms", f"{banner_file} permissions are {mode}, expected 644",
                     "low", control, f"chmod 644 {banner_file}")


def check_network_sysctl(violations, checks_run):
    """3.2 / 3.3 Network Parameters"""
    checks = {
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.secure_redirects": "0",
        "net.ipv4.conf.default.secure_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv6.conf.all.accept_ra": "0",
        "net.ipv6.conf.default.accept_ra": "0",
    }
    for param, expected in checks.items():
        checks_run[0] += 1
        out, _ = _run(f"sysctl -n {param} 2>/dev/null")
        if out != expected:
            _add(violations, f"sysctl.{param}", f"{param} is '{out or 'unset'}', expected '{expected}'",
                 "medium", "CIS 3.2/3.3", f"sysctl -w {param}={expected} (persist in /etc/sysctl.d/)")


def check_firewall(violations, checks_run):
    """3.5 Firewall Configuration"""
    checks_run[0] += 1
    out, _ = _run("ufw status | head -1")
    if "active" not in out.lower():
        _add(violations, "firewall.ufw_enabled", "ufw is not active",
             "critical", "CIS 3.5.1.2", "ufw enable")

    checks_run[0] += 1
    out, _ = _run("ufw status verbose 2>/dev/null | grep 'Default:'")
    if "deny (incoming)" not in out:
        _add(violations, "firewall.default_deny", "ufw default incoming policy is not deny",
             "high", "CIS 3.5.1.4", "ufw default deny incoming")


def check_logging(violations, checks_run):
    """4.1 Configure Logging"""
    checks_run[0] += 1
    out, rc = _run("systemctl is-active systemd-journald 2>/dev/null")
    if rc != 0 or "active" not in out:
        _add(violations, "logging.journald", "systemd-journald is not active",
             "high", "CIS 4.1", "systemctl --now enable systemd-journald")

    checks_run[0] += 1
    if os.path.exists("/var/log/journal"):
        pass
    else:
        _add(violations, "logging.persistent_journal", "/var/log/journal does not exist -- journal is not persistent",
             "medium", "CIS 4.1.1.3", "mkdir -p /var/log/journal && systemd-tmpfiles --create --prefix /var/log/journal")


def check_auditd_config(violations, checks_run):
    """4.2 Configure auditd"""
    checks_run[0] += 1
    out, rc = _run("systemctl is-enabled auditd 2>/dev/null")
    if rc != 0 or "enabled" not in out:
        _add(violations, "auditd.enabled", "auditd is not enabled",
             "critical", "CIS 4.2.1.1", "systemctl --now enable auditd")

    checks_run[0] += 1
    out, _ = _run("auditctl -s 2>/dev/null | grep -o 'max_log_file [0-9]*'")
    if not out:
        _add(violations, "auditd.max_log_file", "Could not verify audit log size configuration",
             "low", "CIS 4.2.1.3", "Set max_log_file in /etc/audit/auditd.conf")

    checks_run[0] += 1
    out, _ = _run("grep -E '^space_left_action' /etc/audit/auditd.conf 2>/dev/null")
    if "email" not in out and "single" not in out:
        _add(violations, "auditd.space_left_action", "space_left_action is not set to email/single",
             "medium", "CIS 4.2.1.4", "Set space_left_action = email in /etc/audit/auditd.conf")


def check_cron(violations, checks_run):
    """5.1 Configure cron"""
    checks_run[0] += 1
    out, rc = _run("systemctl is-enabled cron 2>/dev/null")
    if rc != 0 or "enabled" not in out:
        _add(violations, "cron.enabled", "cron service is not enabled",
             "medium", "CIS 5.1.1", "systemctl --now enable cron")

    for f in ["/etc/crontab", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]:
        checks_run[0] += 1
        if os.path.exists(f):
            mode = oct(stat_module.S_IMODE(os.stat(f).st_mode))[2:]
            expected = "600" if os.path.isfile(f) else "700"
            if mode != expected:
                _add(violations, f"cron.perms.{os.path.basename(f)}", f"{f} permissions are {mode}, expected {expected}",
                     "medium", "CIS 5.1.2-5.1.6", f"chmod {expected} {f}")

    checks_run[0] += 1
    if not os.path.exists("/etc/cron.allow"):
        _add(violations, "cron.allow_file", "/etc/cron.allow does not exist",
             "low", "CIS 5.1.8", "touch /etc/cron.allow && chmod 640 /etc/cron.allow")


def check_ssh_hardening(violations, checks_run):
    """5.2 Configure SSH Server (expanded beyond original 3 checks)"""
    sshd_expected = {
        "LogLevel": "VERBOSE",
        "MaxAuthTries": "4",
        "IgnoreRhosts": "yes",
        "HostbasedAuthentication": "no",
        "PermitEmptyPasswords": "no",
        "PermitUserEnvironment": "no",
        "ClientAliveInterval": None,   # just needs to be set, value varies
        "ClientAliveCountMax": None,
        "LoginGraceTime": None,
        "MaxStartups": None,
        "MaxSessions": None,
    }

    sshd_config_lines = {}
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    sshd_config_lines[parts[0]] = parts[1].strip()
    except Exception:
        pass

    for directive, expected in sshd_expected.items():
        checks_run[0] += 1
        actual = sshd_config_lines.get(directive)
        if actual is None:
            _add(violations, f"sshd_config.{directive}", f"SSH directive '{directive}' is not explicitly set",
                 "medium", "CIS 5.2", f"Add '{directive} {expected or '<value>'}' to /etc/ssh/sshd_config")
        elif expected is not None and actual.lower() != expected.lower():
            _add(violations, f"sshd_config.{directive}", f"SSH directive '{directive}' is '{actual}', expected '{expected}'",
                 "medium", "CIS 5.2", f"Set '{directive} {expected}' in /etc/ssh/sshd_config")


def check_pam_pwquality(violations, checks_run):
    """5.3 Configure PAM / pwquality / faillock"""
    checks_run[0] += 1
    out, _ = _run("grep -E '^minlen' /etc/security/pwquality.conf 2>/dev/null")
    m = re.search(r"minlen\s*=\s*(\d+)", out)
    if not m or int(m.group(1)) < 14:
        _add(violations, "pwquality.minlen", f"Password minlen is '{out or 'unset'}', expected >=14",
             "medium", "CIS 5.3.1.1", "Set minlen = 14 in /etc/security/pwquality.conf")

    checks_run[0] += 1
    out, _ = _run("grep -E '^deny' /etc/security/faillock.conf 2>/dev/null")
    m = re.search(r"deny\s*=\s*(\d+)", out)
    if not m or int(m.group(1)) > 5:
        _add(violations, "faillock.deny", f"faillock deny is '{out or 'unset'}', expected <=5",
             "medium", "CIS 5.3.3", "Set deny = 5 in /etc/security/faillock.conf")

    checks_run[0] += 1
    out, _ = _run("grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
    m = re.search(r"PASS_MAX_DAYS\s+(\d+)", out)
    if not m or int(m.group(1)) > 365:
        _add(violations, "login_defs.pass_max_days", f"PASS_MAX_DAYS is '{out or 'unset'}', expected <=365",
             "low", "CIS 5.3.1.4", "Set PASS_MAX_DAYS 365 in /etc/login.defs")


def check_user_accounts(violations, checks_run):
    """5.4 User Accounts and Environment"""
    checks_run[0] += 1
    out, _ = _run("awk -F: '($3 == 0) {print $1}' /etc/passwd")
    uid0_users = [u for u in out.splitlines() if u.strip() and u.strip() != "root"]
    if uid0_users:
        _add(violations, "accounts.uid_zero", f"Non-root accounts with UID 0: {uid0_users}",
             "critical", "CIS 5.4.2", "Investigate and remove UID 0 from non-root accounts immediately")

    checks_run[0] += 1
    out, _ = _run("grep -E '^UMASK' /etc/login.defs 2>/dev/null")
    m = re.search(r"UMASK\s+(\d+)", out)
    if not m or m.group(1) not in ("027", "077"):
        _add(violations, "login_defs.umask", f"Default UMASK is '{out or 'unset'}', expected 027 or 077",
             "medium", "CIS 5.4.4", "Set UMASK 027 in /etc/login.defs")

    checks_run[0] += 1
    out, _ = _run("echo $TMOUT")
    if not out or out == "0":
        _add(violations, "accounts.shell_timeout", "TMOUT (shell auto-logout) is not configured",
             "low", "CIS 5.4.5", "Set TMOUT=900 in /etc/profile.d/ or /etc/bash.bashrc")


def run_all_checks():
    """
    Runs every check group above. Returns (violations_list, total_checks_run).
    """
    violations = []
    checks_run = [0]  # mutable int wrapper so helper functions can increment it

    check_process_hardening(violations, checks_run)
    check_apparmor(violations, checks_run)
    check_banners(violations, checks_run)
    check_network_sysctl(violations, checks_run)
    check_firewall(violations, checks_run)
    check_logging(violations, checks_run)
    check_auditd_config(violations, checks_run)
    check_cron(violations, checks_run)
    check_ssh_hardening(violations, checks_run)
    check_pam_pwquality(violations, checks_run)
    check_user_accounts(violations, checks_run)

    return violations, checks_run[0]


if __name__ == "__main__":
    violations, total = run_all_checks()
    print(f"Total checks run: {total}")
    print(f"Violations found: {len(violations)}")
    print(f"Compliance: {100.0 - (len(violations) / total * 100.0):.2f}%")
    print()
    for v in violations:
        print(f"[{v['severity'].upper()}] {v['entity']}: {v['details']}")
        print(f"  -> {v['recommended_remediation']}")
        print()
