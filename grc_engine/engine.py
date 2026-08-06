import os
import json
import hashlib
import socket
import time
import threading
from typing import Dict, Any, List, Optional
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("grc_engine")

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

class GRCEvidenceEngine:
    def __init__(self, ledger_path: str):
        self.ledger_path = ledger_path
        os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
        # FIX: append_evidence() had no lock -- two processes briefly
        # overlapping during a systemctl restart could both read the
        # "last block hash" at once and each append a block expecting
        # to be next, breaking the chain (exactly what happened tonight,
        # same class of bug as the earlier MetricsEngine race).
        self._lock = threading.Lock()

    def _hash_string(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _calculate_evidence_hash(self, payload: Dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True)
        return self._hash_string(serialized)

    def _get_last_block_hash(self) -> str:
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            return GENESIS_HASH

        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if not lines:
                    return GENESIS_HASH
                last_line = lines[-1].strip()
                if not last_line:
                    return GENESIS_HASH
                last_block = json.loads(last_line)
                return last_block.get("current_hash", GENESIS_HASH)
        except Exception as e:
            logger.error(f"Failed to read last block from ledger: {e}")
            return GENESIS_HASH

    def append_evidence(self, incident_id: str, username: str, chain_data: Dict[str, Any], rules: List[str], tactics: List[str], techniques: List[str], nist_controls: List[str], sox_controls: List[str], risk_score: float, containment_actions: List[str]) -> Dict[str, Any]:
        with self._lock:
            return self._append_evidence_locked(incident_id, username, chain_data, rules, tactics, techniques, nist_controls, sox_controls, risk_score, containment_actions)

    def _append_evidence_locked(self, incident_id: str, username: str, chain_data: Dict[str, Any], rules: List[str], tactics: List[str], techniques: List[str], nist_controls: List[str], sox_controls: List[str], risk_score: float, containment_actions: List[str]) -> Dict[str, Any]:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        hostname = socket.gethostname()

        evidence_payload = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "user": username,
            "mitre_techniques": list(techniques),
            "mitre_tactics": list(tactics),
            "nist_800_53": list(nist_controls),
            "sox_itgc": list(sox_controls),
            "risk_score": float(risk_score),
            "containment_actions": list(containment_actions),
            "attack_chain_summary": {
                "events_count": chain_data.get("events_count", 0),
                "matched_rules_count": chain_data.get("matched_rules_count", 0),
                "rules": chain_data.get("rules", [])
            }
        }

        evidence_hash = self._calculate_evidence_hash(evidence_payload)
        previous_hash = self._get_last_block_hash()
        current_hash = self._hash_string(evidence_hash + previous_hash)

        block = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "user": username,
            "mitre_techniques": list(techniques),
            "mitre_tactics": list(tactics),
            "nist_800_53": list(nist_controls),
            "sox_itgc": list(sox_controls),
            "risk_score": float(risk_score),
            "containment_actions": list(containment_actions),
            "attack_chain_summary": evidence_payload["attack_chain_summary"],
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash,
            "current_hash": current_hash
        }

        try:
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(block) + "\n")
            logger.info(f"Appended GRC evidence block for incident {incident_id} (Hash: {current_hash[:8]})")
        except Exception as e:
            logger.error(f"Failed to append block to ledger: {e}")

        return block

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        if not os.path.exists(self.ledger_path) or os.path.getsize(self.ledger_path) == 0:
            return {
                "integrity_valid": True,
                "tampered_index": None,
                "error_message": "Ledger is empty or does not exist."
            }

        try:
            blocks = []
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        blocks.append(json.loads(line))
        except Exception as e:
            return {
                "integrity_valid": False,
                "tampered_index": -1,
                "error_message": f"Failed to parse ledger file: {e}"
            }

        expected_previous_hash = GENESIS_HASH

        for idx, block in enumerate(blocks):
            if block.get("previous_hash") != expected_previous_hash:
                err_msg = f"Chain link broken at block {idx}. Expected previous hash '{expected_previous_hash[:8]}', got '{block.get('previous_hash')[:8]}'."
                logger.error(err_msg)
                return {"integrity_valid": False, "tampered_index": idx, "error_message": err_msg}

            reconstructed_payload = {
                "incident_id": block.get("incident_id"),
                "timestamp": block.get("timestamp"),
                "hostname": block.get("hostname"),
                "user": block.get("user"),
                "mitre_techniques": block.get("mitre_techniques"),
                "mitre_tactics": block.get("mitre_tactics"),
                "nist_800_53": block.get("nist_800_53"),
                "sox_itgc": block.get("sox_itgc"),
                "risk_score": block.get("risk_score"),
                "containment_actions": block.get("containment_actions"),
                "attack_chain_summary": block.get("attack_chain_summary")
            }

            calc_evidence_hash = self._calculate_evidence_hash(reconstructed_payload)
            if calc_evidence_hash != block.get("evidence_hash"):
                err_msg = f"Internal content tamper detected at block {idx}. Evidence hash mismatch."
                logger.error(err_msg)
                return {"integrity_valid": False, "tampered_index": idx, "error_message": err_msg}

            calc_current_hash = self._hash_string(calc_evidence_hash + expected_previous_hash)
            if calc_current_hash != block.get("current_hash"):
                err_msg = f"Seal broken at block {idx}. Current block hash mismatch."
                logger.error(err_msg)
                return {"integrity_valid": False, "tampered_index": idx, "error_message": err_msg}

            expected_previous_hash = calc_current_hash

        return {"integrity_valid": True, "tampered_index": None, "error_message": None}
