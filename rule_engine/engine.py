import os
import re
import yaml
from typing import Dict, Any, List, Optional, Callable
from lotl_edr.normalizer.schema import NormalizedEvent
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("rule_engine")


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules: List[Dict[str, Any]] = []

        self.operators: Dict[str, Callable[[Any, Any], bool]] = {
            "equal":      self._op_equal,
            "contains":   lambda val, exp: str(exp) in str(val),
            "startswith": lambda val, exp: str(val).startswith(str(exp)),
            "endswith":   lambda val, exp: str(val).endswith(str(exp)),
            "regex":      self._op_regex,
            "in":         self._op_in,
            "gte":        self._op_numeric(lambda v, e: v >= e),
            "gt":         self._op_numeric(lambda v, e: v > e),
            "lte":        self._op_numeric(lambda v, e: v <= e),
            "lt":         self._op_numeric(lambda v, e: v < e),
        }

        self.load_rules()

    def _op_equal(self, val: Any, expected: Any) -> bool:
        if type(val) == type(expected):
            return val == expected
        return str(val).strip() == str(expected).strip()

    def _op_regex(self, val: Any, expected: Any) -> bool:
        try:
            pattern = re.compile(str(expected), re.IGNORECASE)
            return bool(pattern.search(str(val)))
        except re.error as e:
            logger.error(f"Invalid regex operator value '{expected}': {e}")
            return False

    def _op_in(self, val: Any, expected: Any) -> bool:
        if isinstance(expected, list):
            return val in expected
        if isinstance(expected, str):
            items = [x.strip() for x in expected.split(",")]
            return str(val) in items
        return False

    def _op_numeric(self, comparator: Callable[[float, float], bool]) -> Callable[[Any, Any], bool]:
        def fn(val: Any, expected: Any) -> bool:
            try:
                return comparator(float(val), float(expected))
            except (TypeError, ValueError):
                return False
        return fn

    def load_rules(self) -> None:
        self.rules.clear()
        if not os.path.exists(self.rules_dir):
            logger.error(f"Rules directory {self.rules_dir} does not exist.")
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule_data = yaml.safe_load(f)
                        if self._validate_rule_schema(rule_data, filepath):
                            self.rules.append(rule_data)
                            logger.info(f"Loaded rule: {rule_data['name']} ({rule_data['id']})")
                except Exception as e:
                    logger.error(f"Failed to load rule from {filepath}: {e}")

        logger.info(f"Total rules loaded: {len(self.rules)}")

    def _validate_rule_schema(self, rule: Any, filepath: str) -> bool:
        if not isinstance(rule, dict):
            logger.warning(f"Invalid rule format in {filepath}: must be a dictionary.")
            return False

        required_fields = ["id", "name", "severity", "risk_score", "mitre_tactics", "mitre_techniques", "conditions"]
        for field in required_fields:
            if field not in rule:
                logger.warning(f"Rule in {filepath} is missing required field '{field}'.")
                return False

        conds = rule["conditions"]
        if not isinstance(conds, dict) or not ("all" in conds or "any" in conds):
            logger.warning(f"Rule in {filepath} must contain 'all' or 'any' block under 'conditions'.")
            return False

        return True

    def match_event(self, event: NormalizedEvent, session_ctx: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        session_ctx = session_ctx or {}
        matched_alerts = []
        for rule in self.rules:
            try:
                if self._evaluate_conditions(rule["conditions"], event, session_ctx):
                    matched_alerts.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "description": rule.get("description", ""),
                        "severity": rule["severity"],
                        "risk_score": int(rule["risk_score"]),
                        "mitre_tactics": rule["mitre_tactics"],
                        "mitre_techniques": rule["mitre_techniques"],
                        "nist_800_53": rule.get("nist_800_53", []),
                        "sox_itgc": rule.get("sox_itgc", []),
                        "event": event
                    })
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.get('id', 'unknown')} on event {event.event_id}: {e}")
        return matched_alerts

    def _evaluate_conditions(self, cond_block: Dict[str, Any], event: NormalizedEvent, session_ctx: Dict[str, Any]) -> bool:
        if "all" in cond_block:
            all_list = cond_block["all"]
            if not isinstance(all_list, list):
                return False
            for cond in all_list:
                if not self._evaluate_single_condition(cond, event, session_ctx):
                    return False
            if "any" not in cond_block:
                return True

        if "any" in cond_block:
            any_list = cond_block["any"]
            if not isinstance(any_list, list):
                return False
            for cond in any_list:
                if self._evaluate_single_condition(cond, event, session_ctx):
                    return True
            return False

        return True

    def _evaluate_single_condition(self, cond: Dict[str, Any], event: NormalizedEvent, session_ctx: Dict[str, Any]) -> bool:
        field = cond.get("field")
        operator = cond.get("operator")
        expected_value = cond.get("value")

        if not field or not operator:
            return False

        val = getattr(event, field, None)
        if val is None:
            val = event.raw_data.get(field)
        if val is None and field in session_ctx:
            val = session_ctx[field]

        return self._apply_operator(operator, val, expected_value)

    def _apply_operator(self, operator: str, val: Any, expected: Any) -> bool:
        op = operator.lower()

        if op == "exists":
            return (val is not None) == bool(expected)

        if val is None:
            return False

        fn = self.operators.get(op)
        if fn is None:
            logger.warning(f"Unsupported operator encountered: '{operator}'")
            return False

        return fn(val, expected)

    def register_operator(self, name: str, fn: Callable[[Any, Any], bool]) -> None:
        self.operators[name.lower()] = fn
        logger.info(f"Registered custom operator: {name}")
