import os
import re
import time
import threading
from typing import Dict, Any
from lotl_edr.collector.base import BaseCollector
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("collector.auth_log")

class AuthLogCollector(BaseCollector):
    def __init__(self, config: Dict[str, Any], callback=None):
        super().__init__("auth_log", config, callback)
        self.log_path = config.get("log_path", "/var/log/auth.log")
        self.thread = None

        self.ssh_success_pattern = re.compile(
            r"Accepted (?:publickey|password) for (\S+) from (\S+) port (\d+) ssh2"
        )
        self.ssh_failed_pattern = re.compile(
            r"Failed (?:password|publickey) for (invalid user )?(\S+) from (\S+) port (\d+) ssh2"
        )
        self.sudo_pattern = re.compile(
            r"(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)"
        )
        self.pam_session_pattern = re.compile(
            r"pam_unix\((\S+):session\): session opened for user (\S+) by \(uid=(\d+)\)"
        )

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._tail_log, daemon=True)
        self.thread.start()
        logger.info(f"AuthLog collector started. Tailing: {self.log_path}")

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.info("AuthLog collector stopped.")

    def _tail_log(self) -> None:
        if not os.path.exists(self.log_path):
            logger.warning(f"Log path {self.log_path} not found. Running in simulation fallback mode.")
            self._run_simulation_loop()
            return

        try:
            file_handle = open(self.log_path, "r", encoding="utf-8", errors="ignore")
            file_handle.seek(0, os.SEEK_END)
            inode = os.stat(self.log_path).st_ino
        except Exception as e:
            logger.error(f"Failed to open auth log {self.log_path}: {e}")
            return

        while self.running:
            try:
                line = file_handle.readline()
                if not line:
                    time.sleep(0.5)
                    if os.path.exists(self.log_path):
                        curr_stat = os.stat(self.log_path)
                        if curr_stat.st_ino != inode or curr_stat.st_size < file_handle.tell():
                            logger.info("Auth log rotation detected. Re-opening log file.")
                            file_handle.close()
                            file_handle = open(self.log_path, "r", encoding="utf-8", errors="ignore")
                            inode = curr_stat.st_ino
                    continue

                parsed = self.parse_line(line.strip())
                if parsed:
                    self.emit(parsed)

            except Exception as e:
                logger.error(f"Error reading auth log: {e}")
                time.sleep(1)

        file_handle.close()

    def parse_line(self, line: str):
        parts = line.split(":")
        if len(parts) < 4:
            return None

        msg = ":".join(parts[3:]).strip()
        header = parts[2]

        pid = -1
        ppid = -1
        uid = -1
        gid = -1

        pid_match = re.search(r"\[(\d+)\]", header)
        if pid_match:
            pid = int(pid_match.group(1))

        ssh_ok = self.ssh_success_pattern.search(msg)
        if ssh_ok:
            user = ssh_ok.group(1)
            src_ip = ssh_ok.group(2)
            src_port = int(ssh_ok.group(3))
            return {
                "event_type": "auth_session", "pid": pid, "ppid": ppid, "uid": uid, "gid": gid,
                "username": user, "exe": "/usr/sbin/sshd", "cmdline": f"sshd: {user} [accepted]",
                "src_ip": src_ip, "src_port": src_port, "status": "success", "action": "ssh_login",
                "timestamp": self._get_iso_timestamp()
            }

        ssh_fail = self.ssh_failed_pattern.search(msg)
        if ssh_fail:
            user = ssh_fail.group(2)
            src_ip = ssh_fail.group(3)
            src_port = int(ssh_fail.group(4))
            return {
                "event_type": "auth_session", "pid": pid, "ppid": ppid, "uid": uid, "gid": gid,
                "username": user, "exe": "/usr/sbin/sshd", "cmdline": f"sshd: {user} [failed]",
                "src_ip": src_ip, "src_port": src_port, "status": "failure", "action": "ssh_login",
                "timestamp": self._get_iso_timestamp()
            }

        sudo_exec = self.sudo_pattern.search(msg)
        if sudo_exec:
            req_user = sudo_exec.group(1)
            tty = sudo_exec.group(2)
            pwd = sudo_exec.group(3)
            target_user = sudo_exec.group(4)
            cmd = sudo_exec.group(5)
            return {
                "event_type": "privilege_change", "pid": pid, "ppid": ppid, "uid": 0, "gid": 0,
                "username": req_user, "exe": "/usr/bin/sudo", "cmdline": f"sudo -u {target_user} {cmd}",
                "tty": tty, "pwd": pwd, "target_user": target_user,
                "timestamp": self._get_iso_timestamp()
            }

        pam_session = self.pam_session_pattern.search(msg)
        if pam_session:
            service = pam_session.group(1)
            user = pam_session.group(2)
            uid_val = int(pam_session.group(3))
            return {
                "event_type": "auth_session", "pid": pid, "ppid": ppid, "uid": uid_val, "gid": gid,
                "username": user, "exe": f"/usr/sbin/{service}" if service in ["sshd", "cron"] else f"pam_{service}",
                "cmdline": f"{service} session opened for {user}", "status": "success",
                "action": f"{service}_session_open", "timestamp": self._get_iso_timestamp()
            }

        return None

    def _get_iso_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    def _run_simulation_loop(self) -> None:
        sim_events = [
            {
                "event_type": "auth_session", "pid": 20432, "ppid": -1, "uid": -1, "gid": -1,
                "username": "root", "exe": "/usr/sbin/sshd", "cmdline": "sshd: root [failed]",
                "src_ip": "10.0.0.5", "src_port": 50123, "status": "failure", "action": "ssh_login",
                "timestamp": self._get_iso_timestamp()
            },
            {
                "event_type": "auth_session", "pid": 20435, "ppid": -1, "uid": 1000, "gid": 1000,
                "username": "admin", "exe": "/usr/sbin/sshd", "cmdline": "sshd: admin [accepted]",
                "src_ip": "10.0.0.5", "src_port": 50124, "status": "success", "action": "ssh_login",
                "timestamp": self._get_iso_timestamp()
            },
            {
                "event_type": "privilege_change", "pid": 20450, "ppid": -1, "uid": 0, "gid": 0,
                "username": "admin", "exe": "/usr/bin/sudo", "cmdline": "sudo -u root /bin/bash",
                "tty": "pts/1", "pwd": "/home/admin", "target_user": "root",
                "timestamp": self._get_iso_timestamp()
            }
        ]

        for ev in sim_events:
            if not self.running:
                break
            time.sleep(1)
            self.emit(ev)

        while self.running:
            time.sleep(1)
