"""
scanner/runner.py
Runs configured security tools and normalizes their output
into a unified finding schema.
"""

import subprocess
import json
import os
from typing import List, Dict, Any


SEVERITY_MAP_BANDIT = {
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
}

SEVERITY_MAP_SEMGREP = {
    "INFO": "LOW",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
}


class ScannerRunner:
    def __init__(self, target: str, tools: List[str]):
        self.target = os.path.abspath(target)
        self.tools = tools
        self._use_all = "all" in tools

    def run(self) -> List[Dict[str, Any]]:
        findings = []
        if self._use_all or "bandit" in self.tools:
            findings.extend(self._run_bandit())
        if self._use_all or "semgrep" in self.tools:
            findings.extend(self._run_semgrep())
        return findings

    # Bandit
    def _run_bandit(self) -> List[Dict[str, Any]]:
        print("[*] Running Bandit (Python SAST)...")
        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r", self.target,
                    "-f", "json",
                    "-ll",          # include LOW and above
                    "--quiet",
                ],
                capture_output=True,
                text=True,
            )
            # Bandit exits 1 when issues are found — that is expected
            raw = json.loads(result.stdout) if result.stdout.strip() else {}
        except FileNotFoundError:
            print("  [!] bandit not installed — skipping. Install with: pip install bandit")
            return []
        except json.JSONDecodeError:
            print(f"  [!] Could not parse Bandit output: {result.stdout[:200]}")
            return []

        findings = []
        for issue in raw.get("results", []):
            findings.append(self._normalize_bandit(issue))
        print(f"  [bandit] {len(findings)} raw finding(s)")
        return findings

    def _normalize_bandit(self, issue: Dict) -> Dict[str, Any]:
        return {
            "tool": "bandit",
            "rule_id": issue.get("test_id", ""),
            "rule_name": issue.get("test_name", ""),
            "severity": SEVERITY_MAP_BANDIT.get(
                issue.get("issue_severity", "LOW").upper(), "LOW"
            ),
            "confidence": issue.get("issue_confidence", "MEDIUM"),
            "message": issue.get("issue_text", ""),
            "file": issue.get("filename", ""),
            "line": issue.get("line_number", 0),
            "code_snippet": issue.get("code", "").strip(),
            "cwe": issue.get("issue_cwe", {}).get("id", None),
            "more_info": issue.get("more_info", ""),
        }

    # Semgrep
    def _run_semgrep(self) -> List[Dict[str, Any]]:
        print("[*] Running Semgrep (multi-language SAST)...")
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config", "auto",
                    "--json",
                    "--quiet",
                    self.target,
                ],
                capture_output=True,
                text=True,
            )
            raw = json.loads(result.stdout) if result.stdout.strip() else {}
        except FileNotFoundError:
            print("  [!] semgrep not installed — skipping. Install with: pip install semgrep")
            return []
        except json.JSONDecodeError:
            print(f"  [!] Could not parse Semgrep output: {result.stdout[:200]}")
            return []

        findings = []
        for match in raw.get("results", []):
            findings.append(self._normalize_semgrep(match))
        print(f"  [semgrep] {len(findings)} raw finding(s)")
        return findings

    def _normalize_semgrep(self, match: Dict) -> Dict[str, Any]:
        severity_raw = match.get("extra", {}).get("severity", "WARNING").upper()
        return {
            "tool": "semgrep",
            "rule_id": match.get("check_id", ""),
            "rule_name": match.get("check_id", "").split(".")[-1],
            "severity": SEVERITY_MAP_SEMGREP.get(severity_raw, "MEDIUM"),
            "confidence": "MEDIUM",
            "message": match.get("extra", {}).get("message", ""),
            "file": match.get("path", ""),
            "line": match.get("start", {}).get("line", 0),
            "code_snippet": match.get("extra", {}).get("lines", "").strip(),
            "cwe": None,
            "more_info": match.get("extra", {}).get("metadata", {}).get("references", [""])[0]
            if match.get("extra", {}).get("metadata", {}).get("references")
            else "",
        }
