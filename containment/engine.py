import os
import shutil
import uuid
import time
import subprocess
import platform
from typing import Dict, Any, List, Optional, Set, Callable
from lotl_edr.process_lineage.engine import ProcessLineageEngine
from lotl_edr.correlator.models import AttackChain
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("containment")


class ContainmentAction:
    def __init__(self, action_type: str, target: str, reversal_cmd: str = "", reversal_data: Optional[Dict[str, Any]] = None):
        self.action_id: str = str(uuid.uuid4())
        self.timestamp: float = time.time()
        self.action_type: str = action_type
        self.target: str = target
        self.reversal_cmd: str = reversal_cmd
        self.reversal_data: Dict[str, Any] = reversal_data or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "timestamp": self.timestamp,
            "action_type": self.action_type,
            "target": self.target,
            "reversal_cmd": self.reversal_cmd,
            "reversal_data": self.reversal_data
        }


class ContainmentEngine:
    def __init__(self, lineage_engine: ProcessLineageEngine, quarantine_dir: str, protected_users: Optional[Set[str]] = None):
        self.lineage_engine = lineage_engine
        self.quarantine_dir = quarantine_dir
        self.active_actions: Dict[str, ContainmentAction] = {}
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.is_linux = (platform.system() == "Linux")
        self.is_root = False
        if self.is_linux:
            try:
                self.is_root = (os.geteuid() == 0)
            except AttributeError:
                pass

        self.protected_users: Set[str] = protected_users or set()

        self.revert_handlers: Dict[str, Callable[["ContainmentAction"], bool]] = {
            "BLOCK_IP": self._revert_block_ip,
            "QUARANTINE_FILE": self._revert_quarantine_file,
            "USER_LOCKOUT": self._revert_user_lockout,
            "KILL_PROCESS": self._revert_noop_success,
            "USER_SESSION_LOCKOUT": self._revert_noop_success,
            "USER_LOCKOUT_SKIPPED": self._revert_noop_success,
        }

    def _is_protected(self, username: Optional[str]) -> bool:
        return bool(username) and username in self.protected_users

    def register_action_type(self, action_type: str, revert_handler: Callable[["ContainmentAction"], bool]) -> None:
        self.revert_handlers[action_type] = revert_handler
        logger.info(f"Registered custom containment action type: {action_type}")

    def execute_high_containment(self, chain: AttackChain, target_pid: int, target_ip: Optional[str] = None, file_path: Optional[str] = None) -> List[str]:
        logger.warning(f"EXECUTING HIGH CONTAINMENT on Attack Chain {chain.chain_id}")
        action_ids = []

        descendants = self.lineage_engine.get_descendants(target_pid, include_exited=False)
        for pid in descendants:
            if pid is not None and pid > 1:
                if self._pid_belongs_to_protected_user(pid):
                    logger.warning(f"Skipping termination of PID {pid} — belongs to protected user.")
                    continue
                action = self._terminate_pid(pid)
                self.active_actions[action.action_id] = action
                action_ids.append(action.action_id)

        if target_ip:
            action = self._block_ip(target_ip)
            self.active_actions[action.action_id] = action
            action_ids.append(action.action_id)

        if file_path and os.path.exists(file_path):
            action = self._quarantine_file(file_path)
            if action:
                self.active_actions[action.action_id] = action
                action_ids.append(action.action_id)

        return action_ids

    def execute_critical_containment(self, chain: AttackChain, root_pid: int, session_id: Optional[int] = None, username: Optional[str] = None, evict_session: bool = True) -> List[str]:
        if self._is_protected(username):
            logger.warning(
                f"CRITICAL CONTAINMENT BLOCKED for protected user '{username}' "
                f"(Attack Chain {chain.chain_id}). No actions taken."
            )
            return []

        logger.critical(f"EXECUTING CRITICAL CONTAINMENT on Attack Chain {chain.chain_id}")
        action_ids = []

        pids_to_kill = [root_pid]
        pids_to_kill.extend(self.lineage_engine.get_descendants(root_pid, include_exited=False))

        for pid in pids_to_kill:
            if pid is not None and pid > 1:
                if self._pid_belongs_to_protected_user(pid):
                    logger.warning(f"Skipping termination of PID {pid} — belongs to protected user.")
                    continue
                action = self._terminate_pid(pid)
                self.active_actions[action.action_id] = action
                action_ids.append(action.action_id)

        if username and username != "root" and not self._is_protected(username):
            action = self._lock_user(username)
            self.active_actions[action.action_id] = action
            action_ids.append(action.action_id)

        if session_id is not None:
            ssh_action = ContainmentAction(
                action_type="USER_SESSION_LOCKOUT",
                target=f"Session_{session_id}",
                reversal_cmd=f"logger 'Reversed session lockout for session {session_id}'"
            )
            self.active_actions[ssh_action.action_id] = ssh_action
            action_ids.append(ssh_action.action_id)
            logger.info(f"Terminated user session {session_id}")

        # FIX: killing the triggering PID's descendants only removes the
        # ONE flagged command's own children -- the attacker's login
        # shell (and its sshd session) is the PARENT of each command, so
        # it was never in the kill target and survived indefinitely.
        # USER_SESSION_LOCKOUT was also a log-only placeholder that never
        # actually terminated anything. This kills every process owned
        # by the attacker's account, genuinely evicting the whole
        # interactive session -- but only once evict_session is True
        # (gated in main.py on 4+ distinct corroborating attack rules),
        # not on every single Confirmed/Critical event.
        if evict_session and username and username != "root" and not self._is_protected(username):
            try:
                subprocess.run(f"pkill -KILL -u {username}", shell=True, capture_output=True, timeout=5)
                kill_action = ContainmentAction(
                    action_type="SESSION_TERMINATED",
                    target=f"user:{username}",
                    reversal_cmd="N/A - killed processes cannot be un-killed"
                )
                self.active_actions[kill_action.action_id] = kill_action
                action_ids.append(kill_action.action_id)
                logger.critical(f"Terminated ALL processes for user '{username}' -- session fully evicted.")
            except Exception as e:
                logger.error(f"Failed to terminate full session for user '{username}': {e}")

        return action_ids

    def _pid_belongs_to_protected_user(self, pid: int) -> bool:
        if not self.protected_users:
            return False
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        import pwd
                        uname = pwd.getpwuid(uid).pw_name
                        return uname in self.protected_users
        except Exception:
            pass
        return False

    def revert_action(self, action_id: str) -> bool:
        action = self.active_actions.get(action_id)
        if not action:
            logger.error(f"Action ID {action_id} not found in active actions.")
            return False

        logger.info(f"ROLLING BACK containment action: {action.action_type} on target {action.target}")

        handler = self.revert_handlers.get(action.action_type)
        if handler is None:
            logger.error(f"No revert handler registered for action type '{action.action_type}'.")
            return False

        success = handler(action)

        if success:
            self.active_actions.pop(action_id)
            logger.info(f"Successfully rolled back action {action_id}")
        return success

    def _revert_block_ip(self, action: ContainmentAction) -> bool:
        if self.is_linux and self.is_root:
            res = subprocess.run(action.reversal_cmd, shell=True, capture_output=True, text=True)
            return res.returncode == 0
        logger.info(f"[DRY-RUN] Executed IP unblock: {action.reversal_cmd}")
        return True

    def _revert_quarantine_file(self, action: ContainmentAction) -> bool:
        orig_path = action.reversal_data.get("original_path")
        quarantine_path = action.reversal_data.get("quarantine_path")
        if orig_path and quarantine_path and os.path.exists(quarantine_path):
            try:
                os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                shutil.move(quarantine_path, orig_path)
                logger.info(f"Restored quarantined file from {quarantine_path} to {orig_path}")
                return True
            except Exception as e:
                logger.error(f"Failed to restore quarantined file: {e}")
                return False
        logger.error("Failed to restore quarantined file: missing metadata or file not found in quarantine.")
        return False

    def _revert_user_lockout(self, action: ContainmentAction) -> bool:
        if self.is_linux and self.is_root:
            res = subprocess.run(action.reversal_cmd, shell=True, capture_output=True, text=True)
            return res.returncode == 0
        logger.info(f"[DRY-RUN] Executed user unlock: {action.reversal_cmd}")
        return True

    def _revert_noop_success(self, action: ContainmentAction) -> bool:
        logger.info(f"'{action.action_type}' rollback complete (no reversible state to restore).")
        return True

    def _terminate_pid(self, pid: int) -> ContainmentAction:
        logger.warning(f"Terminating malicious process PID: {pid}")
        try:
            if platform.system() == "Windows":
                subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
            else:
                subprocess.run(f"kill -9 {pid}", shell=True, capture_output=True)
        except Exception:
            pass

        self.lineage_engine.terminate_process(pid)

        return ContainmentAction(
            action_type="KILL_PROCESS",
            target=str(pid),
            reversal_cmd="logger 'Process termination cannot be undone.'"
        )

    def _block_ip(self, ip: str) -> ContainmentAction:
        logger.warning(f"Blocking outbound network traffic to IP: {ip}")
        block_cmd = f"iptables -A OUTPUT -d {ip} -j DROP"
        revert_cmd = f"iptables -D OUTPUT -d {ip} -j DROP"

        if self.is_linux and self.is_root:
            # FIX: check if this exact rule already exists before adding
            # another -- containment re-firing on an ongoing chain was
            # stacking up duplicate identical DROP rules every time.
            check_cmd = f"iptables -C OUTPUT -d {ip} -j DROP"
            already_blocked = subprocess.run(check_cmd, shell=True, capture_output=True).returncode == 0
            if not already_blocked:
                subprocess.run(block_cmd, shell=True, capture_output=True)
            else:
                logger.info(f"IP {ip} already blocked, skipping duplicate rule.")
        else:
            logger.info(f"[DRY-RUN] Executed block command: {block_cmd}")

        return ContainmentAction(action_type="BLOCK_IP", target=ip, reversal_cmd=revert_cmd)

    def _quarantine_file(self, filepath: str) -> Optional[ContainmentAction]:
        logger.warning(f"Quarantining file: {filepath}")
        filename = os.path.basename(filepath)
        q_filename = f"{filename}_{uuid.uuid4().hex}"
        q_filepath = os.path.join(self.quarantine_dir, q_filename)

        try:
            shutil.move(filepath, q_filepath)
            with open(filepath + ".quarantined", "w") as f:
                f.write(f"FILE REMOVED BY LoTL EDR PLATFORM\nQuarantine ID: {q_filename}\n")

            return ContainmentAction(
                action_type="QUARANTINE_FILE",
                target=filepath,
                reversal_cmd="",
                reversal_data={"original_path": filepath, "quarantine_path": q_filepath}
            )
        except Exception as e:
            logger.error(f"Failed to quarantine file {filepath}: {e}")
            return None

    def _lock_user(self, username: str) -> ContainmentAction:
        if self._is_protected(username):
            logger.warning(f"Refusing to lock protected user account: {username}")
            return ContainmentAction(action_type="USER_LOCKOUT_SKIPPED", target=username)

        logger.warning(f"Locking account for user: {username}")
        lock_cmd = f"passwd -l {username}"
        unlock_cmd = f"passwd -u {username}"

        if self.is_linux and self.is_root:
            subprocess.run(lock_cmd, shell=True, capture_output=True)
        else:
            logger.info(f"[DRY-RUN] Executed user lock command: {lock_cmd}")

        return ContainmentAction(action_type="USER_LOCKOUT", target=username, reversal_cmd=unlock_cmd)
