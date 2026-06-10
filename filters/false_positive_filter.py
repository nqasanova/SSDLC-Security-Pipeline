"""
filters/false_positive_filter.py
Filters out false positive findings based on configurable rules.

Rules are defined in filters/fp_rules.yaml and support:
  - rule_id matching (exact or prefix)
  - file path pattern matching (glob)
  - message keyword matching
  - combined conditions (all must match)
"""

import os
import fnmatch
from typing import List, Dict, Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


DEFAULT_RULES = [
    # Test files — security issues in tests are usually intentional
    {
        "description": "Suppress all findings in test files",
        "file_pattern": "*/test*",
    },
    {
        "description": "Suppress all findings in test files (tests/ directory)",
        "file_pattern": "tests/*",
    },
    # Bandit B101 — assert statements in non-production code
    {
        "description": "Suppress B101 assert_used in test files",
        "rule_id": "B101",
        "file_pattern": "*test*",
    },
    # Bandit B311 — random module usage in non-security contexts
    {
        "description": "Suppress B311 random in sample/demo code",
        "rule_id": "B311",
        "file_pattern": "*sample*",
    },
    # Suppress low-confidence findings from Semgrep auto config
    # that relate to documentation or example code
    {
        "description": "Suppress findings in docs directory",
        "file_pattern": "docs/*",
    },
]


class FalsePositiveFilter:
    def __init__(self, config_path: str):
        self.rules = self._load_rules(config_path)

    def _load_rules(self, config_path: str) -> List[Dict]:
        if YAML_AVAILABLE and os.path.exists(config_path):
            try:
                with open(config_path) as fh:
                    data = yaml.safe_load(fh)
                    loaded = data.get("rules", []) if data else []
                    print(f"  [filter] Loaded {len(loaded)} FP rule(s) from {config_path}")
                    return loaded
            except Exception as e:
                print(f"  [filter] Could not load {config_path}: {e} — using defaults")
        else:
            if not os.path.exists(config_path):
                print(f"  [filter] No FP config found at {config_path} — using built-in defaults")
        return DEFAULT_RULES

    def filter(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        confirmed = []
        for finding in findings:
            if not self._is_false_positive(finding):
                confirmed.append(finding)
        return confirmed

    def _is_false_positive(self, finding: Dict[str, Any]) -> bool:
        for rule in self.rules:
            if self._rule_matches(rule, finding):
                finding["suppressed_by"] = rule.get("description", "unnamed rule")
                return True
        return False

    def _rule_matches(self, rule: Dict, finding: Dict[str, Any]) -> bool:
        """All conditions present in a rule must match for it to apply."""
        file_path = finding.get("file", "")
        rule_id = finding.get("rule_id", "")
        message = finding.get("message", "")

        # File pattern condition
        if "file_pattern" in rule:
            pattern = rule["file_pattern"]
            # Match against full path and basename
            if not (
                fnmatch.fnmatch(file_path, pattern)
                or fnmatch.fnmatch(os.path.basename(file_path), pattern)
                or fnmatch.fnmatch(file_path, f"*/{pattern}")
            ):
                return False

        # Rule ID condition (exact or prefix match)
        if "rule_id" in rule:
            expected = rule["rule_id"]
            if not (rule_id == expected or rule_id.startswith(expected)):
                return False

        # Message keyword condition
        if "message_contains" in rule:
            keyword = rule["message_contains"].lower()
            if keyword not in message.lower():
                return False

        return True
