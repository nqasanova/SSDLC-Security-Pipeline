"""
scanner/metrics.py
Tracks vulnerability counts over time so the dashboard can show trends.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


class MetricsTracker:
    def __init__(self, metrics_file: str):
        self.metrics_file = metrics_file
        os.makedirs(os.path.dirname(metrics_file), exist_ok=True)

    def record(self, findings: List[Dict[str, Any]]) -> None:
        history = self.load_history()

        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "total": 0}
        by_tool = {}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
            counts["total"] += 1
            tool = f.get("tool", "unknown")
            by_tool[tool] = by_tool.get(tool, 0) + 1

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "counts": counts,
            "by_tool": by_tool,
        }
        history.append(entry)

        with open(self.metrics_file, "w") as fh:
            json.dump(history, fh, indent=2)

    def load_history(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.metrics_file):
            return []
        try:
            with open(self.metrics_file) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
