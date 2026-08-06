import os
import time
import threading
import socket
import struct
import pwd
from typing import Dict, Any, List, Set, Tuple
from lotl_edr.collector.base import BaseCollector
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("collector.network")

class NetworkCollector(BaseCollector):
    def __init__(self, config: Dict[str, Any], callback=None):
        super().__init__("network", config, callback)
        self.interval = config.get("scan_interval_sec", 5)
        self.thread = None
        self.seen_connections = set()
        self.is_linux = os.path.exists("/proc/net/tcp")

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info("Network collector started.")

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.info("Network collector stopped.")

    def _run(self) -> None:
        try:
            self.scan()
        except Exception as e:
            logger.error(f"Error during initial Network scan: {e}")

        while self.running:
            time.sleep(self.interval)
            if not self.running:
                break
            try:
                self.scan()
            except Exception as e:
                logger.error(f"Error during Network scan: {e}")

    def scan(self) -> None:
        if not self.is_linux:
            self._simulate_scan()
            return

        inode_to_pid = self._map_inodes_to_pids()

        connections = []
        connections.extend(self._parse_net_file("/proc/net/tcp", "tcp", inode_to_pid))
        connections.extend(self._parse_net_file("/proc/net/udp", "udp", inode_to_pid))
        connections.extend(self._parse_net_file("/proc/net/tcp6", "tcp6", inode_to_pid))
        connections.extend(self._parse_net_file("/proc/net/udp6", "udp6", inode_to_pid))

        current_conn_keys = set()
        for conn in connections:
            conn_key = (conn["pid"], conn["protocol"], conn["src_ip"], conn["src_port"], conn["dst_ip"], conn["dst_port"])
            current_conn_keys.add(conn_key)

            if conn_key not in self.seen_connections:
                self.emit(conn)

        self.seen_connections = current_conn_keys

    def _hex_to_ip_port(self, hex_str: str, family: int) -> Tuple[str, int]:
        parts = hex_str.split(':')
        hex_ip = parts[0]
        hex_port = parts[1]

        port = int(hex_port, 16)

        ip_bytes = bytes.fromhex(hex_ip)
        if family == socket.AF_INET:
            ip = socket.inet_ntop(family, ip_bytes[::-1])
        else:
            unpacked = struct.unpack("<IIII", ip_bytes)
            repacked = struct.pack(">IIII", *unpacked)
            ip = socket.inet_ntop(family, repacked)

        return ip, port

    def _map_inodes_to_pids(self) -> Dict[str, int]:
        inode_map = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link.startswith("socket:["):
                        inode = link[8:-1]
                        inode_map[inode] = pid
            except Exception:
                pass
        return inode_map

    def _parse_net_file(self, filepath: str, proto: str, inode_map: Dict[str, int]) -> List[Dict[str, Any]]:
        if not os.path.exists(filepath):
            return []

        family = socket.AF_INET6 if "6" in proto else socket.AF_INET
        conns = []

        try:
            with open(filepath, "r") as f:
                lines = f.readlines()

            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue

                local_hex = parts[1]
                remote_hex = parts[2]
                state_hex = parts[3]
                inode = parts[9]

                try:
                    src_ip, src_port = self._hex_to_ip_port(local_hex, family)
                    dst_ip, dst_port = self._hex_to_ip_port(remote_hex, family)
                except Exception:
                    continue

                pid = inode_map.get(inode, -1)

                exe = ""
                cmdline = ""
                uid = 0
                gid = 0
                username = "unknown"

                if pid != -1:
                    try:
                        exe = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        pass
                    try:
                        with open(f"/proc/{pid}/cmdline", "r") as cmdf:
                            cmdline = cmdf.read().replace("\x00", " ").strip()
                    except Exception:
                        pass
                    try:
                        with open(f"/proc/{pid}/status", "r") as statf:
                            for s_line in statf:
                                if s_line.startswith("Uid:"):
                                    uid = int(s_line.split()[1])
                                    try:
                                        username = pwd.getpwuid(uid).pw_name
                                    except KeyError:
                                        username = f"uid_{uid}"
                                elif s_line.startswith("Gid:"):
                                    gid = int(s_line.split()[1])
                    except Exception:
                        pass

                conns.append({
                    "pid": pid, "ppid": -1, "uid": uid, "gid": gid, "username": username,
                    "exe": exe, "cmdline": cmdline or (exe.split("/")[-1] if exe else f"proc_{pid}"),
                    "protocol": proto, "src_ip": src_ip, "src_port": src_port,
                    "dst_ip": dst_ip, "dst_port": dst_port, "state": state_hex,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
                })
        except Exception as e:
            logger.debug(f"Failed to parse {filepath}: {e}")

        return conns

    def _simulate_scan(self) -> None:
        sim_events = [
            {
                "pid": 5002, "ppid": -1, "uid": 1000, "gid": 1000,
                "username": "attacker", "exe": "/usr/bin/python3",
                "cmdline": "python3 -c import socket,subprocess,os;...",
                "protocol": "tcp", "src_ip": "192.168.1.50", "src_port": 54321,
                "dst_ip": "10.0.0.5", "dst_port": 4444, "state": "01",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            }
        ]
        for ev in sim_events:
            conn_key = (ev["pid"], ev["protocol"], ev["src_ip"], ev["src_port"], ev["dst_ip"], ev["dst_port"])
            if conn_key not in self.seen_connections:
                self.emit(ev)
                self.seen_connections.add(conn_key)
