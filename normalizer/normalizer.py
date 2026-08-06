import re
from typing import Dict, Any, Optional, List, Tuple
from lotl_edr.normalizer.schema import NormalizedEvent
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("normalizer")

class EventNormalizer:
    def __init__(self):
        self.mitre_heuristics = [
            (re.compile(r"\b(whoami|id|hostname|uname|w|last|netstat|ss|ip\s+a)\b", re.IGNORECASE),
             ["Discovery"], ["T1033", "T1082", "T1049"]),

            (re.compile(r"\b(curl|wget|fetch|tftp|sftp)\b.*\b(http|ftp)\b", re.IGNORECASE),
             ["Command and Control"], ["T1105"]),

            (re.compile(r"/tmp/|/dev/shm/|/var/tmp/", re.IGNORECASE),
             ["Defense Evasion", "Execution"], ["T1204.002", "T1059"]),

            (re.compile(r"\b(nc|netcat|ncat|bash\s+-i|/dev/tcp/|sh\s+-i|python3?\s+-c\s+.*socket)\b", re.IGNORECASE),
             ["Execution", "Command and Control"], ["T1059.004", "T1071"]),

            (re.compile(r"\b(sudo|pkexec|su|setuid|setgid)\b", re.IGNORECASE),
             ["Privilege Escalation"], ["T1548.003", "T1548.001"]),

            (re.compile(r"\b(ssh|scp|rsync|sftp)\b.*\b(root|admin)\b", re.IGNORECASE),
             ["Lateral Movement", "Credential Access"], ["T1021.004", "T1110"]),

            (re.compile(r"\b(cron|crontab|systemctl\s+enable|rc\.local)\b", re.IGNORECASE),
             ["Persistence"], ["T1053.003", "T1543.003"])
        ]

    def normalize(self, raw_event: Dict[str, Any]) -> Optional[NormalizedEvent]:
        collector = raw_event.get("_collector", "unknown")

        try:
            timestamp = raw_event.get("timestamp")
            if not timestamp:
                raise ValueError("Timestamp is required and cannot be empty")
            event_type = raw_event.get("event_type", "unknown")
            pid = self._to_int(raw_event.get("pid"), -1)
            ppid = self._to_int(raw_event.get("ppid"), -1)
            uid = self._to_int(raw_event.get("uid"), -1)
            gid = self._to_int(raw_event.get("gid"), -1)
            session_id = self._to_int(raw_event.get("session_id"), None)
            tty = raw_event.get("tty")

            username = raw_event.get("username", "unknown")
            exe = raw_event.get("exe", "")
            cmdline = raw_event.get("cmdline", "")

            src_ip = raw_event.get("src_ip")
            src_port = self._to_int(raw_event.get("src_port"), None)
            dst_ip = raw_event.get("dst_ip")
            dst_port = self._to_int(raw_event.get("dst_port"), None)

            if collector == "proc_fs":
                event_type = "process_exec"
            elif collector == "network":
                event_type = "network_connect" if dst_ip else "network_accept"
            elif collector == "auth_log":
                pass
            elif collector == "auditd":
                pass
            elif collector == "ebpf":
                pass

            tactics, techniques = self._enrich_mitre_info(cmdline, event_type)

            norm_ev = NormalizedEvent(
                timestamp=timestamp,
                source=collector,
                event_type=event_type,
                pid=pid,
                ppid=ppid,
                uid=uid,
                gid=gid,
                session_id=session_id,
                tty=tty,
                username=username,
                exe=exe,
                cmdline=cmdline,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                raw_data={k: v for k, v in raw_event.items() if not k.startswith("_")}
            )
            return norm_ev

        except Exception as e:
            logger.error(f"Failed to normalize raw event from {collector}. Error: {e}. Event dump: {raw_event}")
            return None

    def _to_int(self, val: Any, default: Any) -> Any:
        if val is None or val == "":
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _enrich_mitre_info(self, cmdline: str, event_type: str) -> Tuple[List[str], List[str]]:
        tactics = []
        techniques = []

        if cmdline:
            for pattern, tac_list, tech_list in self.mitre_heuristics:
                if pattern.search(cmdline):
                    for tac in tac_list:
                        if tac not in tactics:
                            tactics.append(tac)
                    for tech in tech_list:
                        if tech not in techniques:
                            techniques.append(tech)

        if event_type == "privilege_change" and "Privilege Escalation" not in tactics:
            tactics.append("Privilege Escalation")
            if "T1548.003" not in techniques:
                techniques.append("T1548.003")
        elif event_type == "auth_session" and "Lateral Movement" not in tactics:
            pass

        return tactics, techniques
