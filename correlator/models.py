import uuid
import time
from typing import List, Set, Dict, Any
from lotl_edr.normalizer.schema import NormalizedEvent

class AttackChain:
    def __init__(self):
        self.chain_id: str = str(uuid.uuid4())
        self.created_at: float = time.time()
        self.last_updated: float = time.time()
        self.events: List[NormalizedEvent] = []
        self.matched_rules: List[Dict[str, Any]] = []
        self.associated_pids: Set[int] = set()
        self.associated_ppids: Set[int] = set()
        self.associated_sessions: Set[int] = set()
        self.associated_ttys: Set[str] = set()
        self.associated_users: Set[str] = set()
        self.associated_ips: Set[str] = set()
        self.accumulated_risk: float = 0.0

    def add_event(self, event: NormalizedEvent, rules: List[Dict[str, Any]]) -> None:
        self.events.append(event)
        self.last_updated = time.time()

        if event.pid not in [-1, 0, 1]:
            self.associated_pids.add(event.pid)
        if event.ppid not in [-1, 0, 1]:
            self.associated_pids.add(event.ppid)
            self.associated_ppids.add(event.ppid)
        if event.session_id is not None:
            self.associated_sessions.add(event.session_id)
        if event.tty:
            self.associated_ttys.add(event.tty)
        if event.username:
            self.associated_users.add(event.username)
        if event.dst_ip:
            self.associated_ips.add(event.dst_ip)
        if event.src_ip:
            self.associated_ips.add(event.src_ip)

        for rule in rules:
            if not any(r["rule_id"] == rule["rule_id"] for r in self.matched_rules):
                self.matched_rules.append(rule)

    def distinct_attack_tier_rule_count(self) -> int:
        """Count of distinct rule IDs in this chain with high/critical
        severity -- used to gate full-session eviction on genuinely
        multi-stage, corroborated attacks rather than one noisy signal
        (e.g. a repeated brute-force rule alone) inflating the score."""
        return len({r["rule_id"] for r in self.matched_rules if r.get("severity", "").lower() in ("high", "critical")})

    def merge_with(self, other: 'AttackChain') -> None:
        self.events.extend(other.events)
        self.events.sort(key=lambda e: e.timestamp)

        self.last_updated = max(self.last_updated, other.last_updated)
        self.created_at = min(self.created_at, other.created_at)

        self.associated_pids.update(other.associated_pids)
        self.associated_ppids.update(other.associated_ppids)
        self.associated_sessions.update(other.associated_sessions)
        self.associated_ttys.update(other.associated_ttys)
        self.associated_users.update(other.associated_users)
        self.associated_ips.update(other.associated_ips)

        for rule in other.matched_rules:
            if not any(r["rule_id"] == rule["rule_id"] for r in self.matched_rules):
                self.matched_rules.append(rule)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "events_count": len(self.events),
            "matched_rules_count": len(self.matched_rules),
            "rules": [r["rule_id"] for r in self.matched_rules],
            "associated_pids": list(self.associated_pids),
            "associated_sessions": list(self.associated_sessions),
            "associated_users": list(self.associated_users),
            "associated_ips": list(self.associated_ips),
            "protected_skip": getattr(self, "protected_skip", False),
            "already_contained": getattr(self, "already_contained", False),
            "events": [(e.model_dump() if hasattr(e, "model_dump") else e.dict()) for e in self.events]
        }
