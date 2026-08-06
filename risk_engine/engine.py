import time
from typing import Dict, Any, Optional
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("risk_engine")

class RiskRecord:
    def __init__(self, initial_score: float = 0.0):
        self.score: float = initial_score
        self.last_updated: float = time.time()

class RiskEngine:
    def __init__(self, half_life_sec: float = 60.0):
        self.half_life_sec: float = half_life_sec
        self.users_risk: Dict[str, RiskRecord] = {}
        self.sessions_risk: Dict[int, RiskRecord] = {}
        self.processes_risk: Dict[int, RiskRecord] = {}
        self.chains_risk: Dict[str, RiskRecord] = {}

    def _decay(self, record: RiskRecord) -> float:
        elapsed = time.time() - record.last_updated
        if elapsed < 0:
            elapsed = 0.0

        decayed_score = record.score * (0.5 ** (elapsed / self.half_life_sec))
        return decayed_score

    def add_alert(self, user: str, session_id: Optional[int], pid: int, chain_id: str, score: float) -> None:
        now = time.time()
        logger.info(f"Aggregating alert risk +{score} (User: {user}, Session: {session_id}, PID: {pid}, Chain: {chain_id})")

        if user:
            if user not in self.users_risk:
                self.users_risk[user] = RiskRecord()
            rec = self.users_risk[user]
            rec.score = self._decay(rec) + score
            rec.last_updated = now

        if session_id is not None:
            if session_id not in self.sessions_risk:
                self.sessions_risk[session_id] = RiskRecord()
            rec = self.sessions_risk[session_id]
            rec.score = self._decay(rec) + score
            rec.last_updated = now

        if pid not in [0, 1, -1]:
            if pid not in self.processes_risk:
                self.processes_risk[pid] = RiskRecord()
            rec = self.processes_risk[pid]
            rec.score = self._decay(rec) + score
            rec.last_updated = now

        if chain_id:
            if chain_id not in self.chains_risk:
                self.chains_risk[chain_id] = RiskRecord()
            rec = self.chains_risk[chain_id]
            rec.score = self._decay(rec) + score
            rec.last_updated = now

    def get_user_risk(self, user: str) -> float:
        if user not in self.users_risk:
            return 0.0
        return self._decay(self.users_risk[user])

    def get_session_risk(self, session_id: int) -> float:
        if session_id not in self.sessions_risk:
            return 0.0
        return self._decay(self.sessions_risk[session_id])

    def get_process_risk(self, pid: int) -> float:
        if pid not in self.processes_risk:
            return 0.0
        return self._decay(self.processes_risk[pid])

    def get_chain_risk(self, chain_id: str) -> float:
        if chain_id not in self.chains_risk:
            return 0.0
        return self._decay(self.chains_risk[chain_id])

    def update_chain_risk(self, chain, alerts) -> float:
        user = list(chain.associated_users)[0] if chain.associated_users else "unknown"
        session_id = list(chain.associated_sessions)[0] if chain.associated_sessions else None

        for alert in alerts:
            score = alert.get("risk_score", alert.get("risk_weight", 10.0))
            pid = alert.get("pid", -1)
            self.add_alert(user, session_id, pid, chain.chain_id, score)

        chain.accumulated_risk = self.get_chain_risk(chain.chain_id)
        return chain.accumulated_risk
