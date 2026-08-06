from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import uuid

class NormalizedEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str  # UTC ISO8601 string format (e.g. YYYY-MM-DDTHH:MM:SS.ffffffZ)
    source: str     # ebpf, auditd, auth_log, proc_fs, network
    event_type: str # process_exec, process_fork, network_connect, network_accept, file_modify, file_delete, privilege_change, auth_session
    pid: int
    ppid: int
    uid: int
    gid: int
    session_id: Optional[int] = None
    tty: Optional[str] = None
    username: str
    exe: str
    cmdline: str
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
